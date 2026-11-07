import json
from collections.abc import Sequence
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Any, ClassVar, cast
from uuid import UUID

import pytest
from typed_columns import typed

from sql_safe_mcp.config import PiiConfig, PiiRule, RuntimeConfig
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import SQLSERVER
from sql_safe_mcp.security.executor import execute_validated
from sql_safe_mcp.security.pipeline import validate_sql
from sql_safe_mcp.security.schema import ColumnSchema
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.security.validated_query import ValidatedQuery

KEY = bytes(range(32))
CODEC = TokenCodec("srv", KEY)
RUNTIME = RuntimeConfig(default_max_rows=3, hard_max_rows=10)
PII = PiiConfig(rules=[PiiRule(database="*", schema="dbo", table="Users", columns=["Email"])])


class Catalog:
    tables: ClassVar[dict[tuple[str, str], list[str]]] = {
        ("dbo", "Users"): ["Id", "Email", "Name"],
    }

    def list_tables(self) -> list[tuple[str, str]]:
        return list(self.tables)

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        return typed(self.tables[(schema, table)])


class FakeResult:
    def __init__(self, keys: Sequence[str], rows: Sequence[tuple[Any, ...]]) -> None:
        self._keys = list(keys)
        self._rows = list(rows)
        self.fetch_sizes: list[int] = []
        self.closed = False

    def keys(self) -> list[str]:
        return self._keys

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        self.fetch_sizes.append(size)
        return self._rows[:size]

    def close(self) -> None:
        self.closed = True


class RecordingConnection:
    def __init__(self, result: FakeResult) -> None:
        self.result = result
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def exec_driver_sql(self, statement: str, parameters: tuple[Any, ...]) -> FakeResult:
        self.calls.append((statement, parameters))
        return self.result


def token(value: object) -> str:
    return f"'{CODEC.encrypt(value)}'"


def build(sql: str, max_rows: int = 3) -> ValidatedQuery:
    return validate_sql(
        sql,
        alias="srv",
        database="app",
        catalog=Catalog(),
        pii_config=PII,
        codec=CODEC,
        runtime=RUNTIME,
        max_rows=max_rows,
        dialect=SQLSERVER,
    )


def run(sql: str, rows: Sequence[tuple[Any, ...]], max_rows: int = 3, keys: Sequence[str] = ("a",)):
    query = build(sql, max_rows)
    connection = RecordingConnection(FakeResult(keys, rows))
    return query, connection, execute_validated(connection, query, CODEC)


def test_executes_generated_sql_and_separate_parameters_once() -> None:
    query, connection, _ = run(
        f"SELECT Id FROM Users WHERE Email = {token('a@b.c')}", [(1,)], keys=["Id"]
    )
    assert connection.calls == [(query.sql, ("a@b.c",))]
    assert "a@b.c" not in connection.calls[0][0]
    assert connection.result.closed


def test_only_a_validated_query_is_accepted() -> None:
    connection = RecordingConnection(FakeResult(["a"], []))
    for raw in ("SELECT 1", object(), None):
        with pytest.raises(TypeError):
            execute_validated(connection, cast(Any, raw), CODEC)
    assert connection.calls == []


def test_codec_of_another_alias_is_refused() -> None:
    connection = RecordingConnection(FakeResult(["Id"], []))
    with pytest.raises(TypeError):
        execute_validated(connection, build("SELECT Id FROM Users"), TokenCodec("other", KEY))
    assert connection.calls == []


@pytest.mark.parametrize(
    ("available", "expected_rows", "truncated"),
    [(0, 0, False), (2, 2, False), (3, 3, False), (4, 3, True), (50, 3, True)],
)
def test_row_cap_and_truncation(available: int, expected_rows: int, truncated: bool) -> None:
    _, connection, result = run("SELECT Id FROM Users", [(i,) for i in range(available)], 3, ["Id"])
    assert connection.result.fetch_sizes == [4]
    assert len(result.rows) == expected_rows
    assert result.truncated is truncated
    assert connection.result.closed


def test_user_top_below_the_cap_is_not_truncated() -> None:
    _, _, result = run("SELECT TOP 2 Id FROM Users", [(1,), (2,)], 3, ["Id"])
    assert result.truncated is False


def test_protected_cells_are_tokenized_and_null_stays_null() -> None:
    _, _, result = run(
        "SELECT Email, Id, Name FROM Users",
        [("a@b.c", 1, "n"), (None, 2, None)],
        keys=["Email", "Id", "Name"],
    )
    assert [c.protected for c in result.columns] == [True, False, False]
    assert [c.encoding for c in result.columns] == ["token", "json", "json"]
    first, second = result.rows
    assert first[0].startswith("pii:v1:")
    assert CODEC.decrypt(first[0]) == "a@b.c"
    assert second == (None, 2, None)
    assert "a@b.c" not in json.dumps(result.rows)


def test_protected_cells_are_tokenized_with_the_domain_of_their_column() -> None:
    config = PiiConfig(
        rules=[PiiRule(database="*", schema="dbo", table="Users", columns=["Email"], domain="pii")]
    )
    query = validate_sql(
        "SELECT Email, Name FROM Users",
        alias="srv",
        database="app",
        catalog=Catalog(),
        pii_config=config,
        codec=CODEC,
        runtime=RUNTIME,
        max_rows=3,
        dialect=SQLSERVER,
    )
    connection = RecordingConnection(FakeResult(["Email", "Name"], [("a@b.c", "n")]))
    result = execute_validated(connection, query, CODEC)
    cell = result.rows[0][0]
    assert CODEC.decrypt(cell, "pii") == "a@b.c"
    with pytest.raises(DomainError):
        CODEC.decrypt(cell)
    assert result.rows[0][1] == "n"


def test_token_length_does_not_depend_on_plaintext_length_within_a_bucket() -> None:
    sql = "SELECT Email, Id FROM Users"
    keys = ["Email", "Id"]
    _, _, short = run(sql, [("abc", 1), (None, 2)], keys=keys)
    _, _, long = run(sql, [("a" * 20, 1), (None, 2)], keys=keys)
    assert short.columns == long.columns
    assert short.truncated == long.truncated
    assert short.rows[1] == long.rows[1]
    assert short.rows[0][1] == long.rows[0][1]
    assert short.rows[0][0] != long.rows[0][0]
    assert len(short.rows[0][0]) == len(long.rows[0][0])


def test_protected_marker_never_appears_in_the_response() -> None:
    marker = "PII-MARKER-7f3a"
    _, _, result = run("SELECT Email FROM Users", [(marker,)], keys=["Email"])
    assert marker not in json.dumps(result.rows) + repr(result.columns)


def test_tokens_round_trip_into_predicates() -> None:
    _, _, result = run("SELECT Email FROM Users", [("a@b.c",)], keys=["Email"])
    again = build(f"SELECT Id FROM Users WHERE Email = '{result.rows[0][0]}'")
    assert again.parameters == ("a@b.c",)


def test_columns_are_positional_with_lineage() -> None:
    _, _, result = run(
        "SELECT Id AS Email, Email AS Id FROM Users",
        [(1, "x")],
        keys=["Email", "Id"],
    )
    assert [(c.name, c.protected) for c in result.columns] == [("Email", False), ("Id", True)]
    assert result.columns[1].source is not None
    assert result.columns[1].source.column == "Email"
    assert result.columns[0].source is not None
    assert result.columns[0].source.column == "Id"


def test_column_count_mismatch_is_an_error() -> None:
    connection = RecordingConnection(FakeResult(["only"], [(1,)]))
    with pytest.raises(DomainError) as info:
        execute_validated(connection, build("SELECT Id, Name FROM Users"), CODEC)
    assert info.value.code is ErrorCode.DATABASE_ERROR
    assert connection.result.closed


@pytest.mark.parametrize(
    ("value", "encoded", "encoding"),
    [
        ("s", "s", "json"),
        (1, 1, "json"),
        (True, True, "json"),
        (1.5, 1.5, "json"),
        (Decimal("1.50"), "1.50", "decimal"),
        (date(2024, 1, 2), "2024-01-02", "date"),
        (time(1, 2, 3), "01:02:03", "time"),
        (timedelta(hours=1, minutes=2, seconds=3), "01:02:03", "time"),
        (timedelta(0), "00:00:00", "time"),
        (timedelta(seconds=1, microseconds=5), "00:00:01.000005", "time"),
        (datetime(2024, 1, 2, 3, 4, 5), "2024-01-02T03:04:05", "datetime"),
        (datetime(2024, 1, 2, tzinfo=UTC), "2024-01-02T00:00:00+00:00", "datetime"),
        (UUID(int=1), "00000000-0000-0000-0000-000000000001", "uuid"),
        (b"\x00\xff", "AP8=", "base64"),
        (bytearray(b"\x00\xff"), "AP8=", "base64"),
        (memoryview(b"\x00\xff"), "AP8=", "base64"),
    ],
)
def test_unprotected_value_encoding_contract(value: Any, encoded: Any, encoding: str) -> None:
    _, _, result = run("SELECT Id FROM Users", [(value,)], keys=["Id"])
    assert result.rows == ((encoded,),)
    assert result.columns[0].encoding == encoding
    json.dumps(result.rows)


def test_all_null_column_defaults_to_json() -> None:
    _, _, result = run("SELECT Id FROM Users", [(None,), (None,)], keys=["Id"])
    assert result.columns[0].encoding == "json"


@pytest.mark.parametrize(
    "value",
    [
        object(),
        float("nan"),
        float("inf"),
        Decimal("NaN"),
        complex(1, 1),
        [1],
        {"a": 1},
        timedelta(days=1),
        timedelta(seconds=-1),
        {"a", "b"},
    ],
)
def test_unsupported_unprotected_values_are_a_controlled_error(value: Any) -> None:
    with pytest.raises(DomainError) as info:
        run("SELECT Id FROM Users", [(value,)], keys=["Id"])
    assert info.value.code is ErrorCode.DATABASE_ERROR


def test_mixed_types_in_one_column_are_a_controlled_error() -> None:
    with pytest.raises(DomainError) as info:
        run("SELECT Id FROM Users", [(1,), (date(2024, 1, 1),)], keys=["Id"])
    assert info.value.code is ErrorCode.DATABASE_ERROR


def test_unsupported_protected_value_fails_closed() -> None:
    with pytest.raises(DomainError) as info:
        run("SELECT Email FROM Users", [(object(),)], keys=["Email"])
    assert info.value.code is ErrorCode.QUERY_REJECTED


def _counted(rows: Sequence[tuple[Any, ...]], threshold: int):
    query = validate_sql(
        # Mixed outputs exercise per-column handling; the fake result supplies the rows.
        "SELECT Name, COUNT(*) AS n, Id FROM Users",
        alias="srv",
        database="app",
        catalog=Catalog(),
        pii_config=PII,
        codec=CODEC,
        runtime=RuntimeConfig(default_max_rows=3, hard_max_rows=10, min_count_cell=threshold),
        max_rows=10,
        dialect=SQLSERVER,
    )
    connection = RecordingConnection(FakeResult(["Name", "n", "Id"], rows))
    return execute_validated(connection, query, CODEC)


def test_counts_below_the_threshold_are_suppressed() -> None:
    result = _counted([("a", 4, 4), ("b", 5, 5), ("c", 0, 0), ("d", 1, 1), ("e", 9, 9)], 5)

    assert result.rows == (("a", None, 4), ("b", 5, 5), ("c", 0, 0), ("d", None, 1), ("e", 9, 9))
    assert [column.encoding for column in result.columns] == ["json", "suppressed", "json"]


def test_count_column_without_small_values_keeps_its_encoding() -> None:
    result = _counted([("a", 5, 1), ("b", 0, 2)], 5)

    assert result.rows == (("a", 5, 1), ("b", 0, 2))
    assert [column.encoding for column in result.columns] == ["json", "json", "json"]


def test_zero_threshold_never_suppresses() -> None:
    result = _counted([("a", 1, 1)], 0)

    assert result.rows == (("a", 1, 1),)
    assert result.columns[1].encoding == "json"


def test_threshold_one_suppresses_nothing() -> None:
    result = _counted([("a", 1, 1)], 1)

    assert result.rows == (("a", 1, 1),)


def test_threshold_applies_only_to_count_outputs() -> None:
    result = _counted([("a", 7, 2)], 5)

    assert result.rows == (("a", 7, 2),)


@pytest.mark.parametrize("value", [Decimal(2), 2.0, True, "2"])
def test_non_integer_count_fails_closed_when_suppressing(value: Any) -> None:
    with pytest.raises(DomainError) as info:
        _counted([("a", value, 1)], 5)
    assert info.value.code is ErrorCode.DATABASE_ERROR


def test_validated_query_carries_the_threshold() -> None:
    query = validate_sql(
        "SELECT COUNT(*) FROM Users",
        alias="srv",
        database="app",
        catalog=Catalog(),
        pii_config=PII,
        codec=CODEC,
        runtime=RuntimeConfig(min_count_cell=11),
        max_rows=3,
        dialect=SQLSERVER,
    )

    assert query.min_count_cell == 11


def test_driver_failures_propagate_to_the_service_layer() -> None:
    class Boom(RecordingConnection):
        def exec_driver_sql(self, statement: str, parameters: tuple[Any, ...]) -> FakeResult:
            raise RuntimeError("driver failure")

    with pytest.raises(RuntimeError):
        execute_validated(Boom(FakeResult(["a"], [])), build("SELECT Id FROM Users"), CODEC)
