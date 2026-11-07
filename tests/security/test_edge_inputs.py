"""Edge inputs and a misbehaving driver: every outcome is a controlled public error."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import pytest
from support import ALIAS, DATABASE, OWN, SpyConnection, SpyResult, spy_service, validate
from support_mysql import validate_mysql

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.models import SqlResult


def _rejected(run: Any, sql: str) -> str:
    with pytest.raises(DomainError) as raised:
        run(sql)
    assert raised.value.code is ErrorCode.QUERY_REJECTED
    return raised.value.public_message


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT TOP ٣ u.Id FROM Users u",  # Arabic-Indic digit three
        "SELECT TOP ² u.Id FROM Users u",  # superscript two
        "SELECT TOP 1e3 u.Id FROM Users u",
        "SELECT TOP 1.5 u.Id FROM Users u",
    ],
)
def test_non_ascii_or_non_integer_top_is_rejected(sql: str) -> None:
    _rejected(validate, sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT u.id FROM users u LIMIT 1e3",
        "SELECT u.id FROM users u LIMIT ٣",
        "SELECT u.id FROM users u LIMIT 1.5",
    ],
)
def test_non_integer_limit_is_rejected(sql: str) -> None:
    _rejected(validate_mysql, sql)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT " + "(" * 1900 + "1" + ")" * 1900 + " AS x FROM Users u",
        "SELECT u.Id FROM Users u WHERE " + "(" * 1900 + "u.Id" + ")" * 1900 + " = 1",
    ],
    ids=["literal", "column"],
)
def test_deep_parenthesis_nesting_is_rejected_without_recursion_errors(sql: str) -> None:
    _rejected(validate, sql)


def _execute(sql: str, keys: list[str], rows: list[tuple[Any, ...]]) -> SqlResult:
    service = spy_service(SpyConnection(SpyResult(keys, rows)))
    return asyncio.run(service.execute_sql(ALIAS, DATABASE, sql))


@pytest.mark.parametrize(
    "value",
    ["2024-01-01 10:00:00.1234567 +03:00", b"\x00\x01sql_variant"],
    ids=["datetimeoffset-text", "variant-bytes"],
)
def test_driver_strings_and_bytes_in_a_protected_cell_become_tokens(value: object) -> None:
    result = _execute("SELECT u.Email FROM Users u", ["Email"], [(value,)])

    cell = result.rows[0][0]
    assert result.columns[0].encoding == "token"
    assert OWN.decrypt(cell) == value


@pytest.mark.parametrize(
    "value",
    [timedelta(hours=30), timedelta(days=-1), object(), 1 + 2j],
    ids=["timedelta-30h", "timedelta-negative", "object", "complex"],
)
def test_untokenizable_protected_cell_fails_closed_without_plaintext(value: object) -> None:
    with pytest.raises(DomainError) as raised:
        _execute("SELECT u.Email FROM Users u", ["Email"], [(value,)])

    assert raised.value.code is ErrorCode.QUERY_REJECTED
    assert str(value) not in str(raised.value)


@pytest.mark.parametrize(
    ("keys", "rows"),
    [
        (["Id", "Name", "Extra"], [(1, "a", "x")]),
        (["Id"], [(1,)]),
        (["Id", "Name"], [(1, "a"), (2,)]),
        (["Id", "Name"], [(1, "a"), (2, "b", "c")]),
    ],
    ids=["extra-column", "missing-column", "short-row", "long-row"],
)
def test_result_shape_drift_is_a_database_error_without_partial_rows(
    keys: list[str], rows: list[tuple[Any, ...]]
) -> None:
    with pytest.raises(DomainError) as raised:
        _execute("SELECT u.Id, u.Name FROM Users u", keys, rows)

    assert raised.value.code is ErrorCode.DATABASE_ERROR
    assert "'a'" not in str(raised.value)
