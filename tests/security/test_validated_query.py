import copy
import pickle
import re
from collections.abc import Callable, Sequence
from typing import ClassVar, cast

import pytest
from sqlglot import exp
from typed_columns import typed

from sql_safe_mcp.config import PiiConfig, PiiRule, RuntimeConfig
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import SQLSERVER
from sql_safe_mcp.security.parser import ParserLimits, parse_select, validate_allowlist
from sql_safe_mcp.security.pipeline import validate_sql
from sql_safe_mcp.security.schema import ColumnSchema
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.security.validated_query import ValidatedQuery

KEY = bytes(range(32))
CODEC = TokenCodec("srv", KEY)
RUNTIME = RuntimeConfig(default_max_rows=200, hard_max_rows=1000)
PII = PiiConfig(rules=[PiiRule(database="*", schema="dbo", table="Users", columns=["Email"])])
INJECTION = "x'; DROP TABLE Canary;--"


class Catalog:
    tables: ClassVar[dict[tuple[str, str], list[str]]] = {
        ("dbo", "Users"): ["Id", "Email", "Name"],
    }

    def __init__(self) -> None:
        self.lookups = 0

    def list_tables(self) -> list[tuple[str, str]]:
        self.lookups += 1
        return list(self.tables)

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        return typed(self.tables[(schema, table)])


def token(value: object) -> str:
    return f"'{CODEC.encrypt(value)}'"


def build(sql: str, max_rows: int = 200, catalog: Catalog | None = None) -> ValidatedQuery:
    return validate_sql(
        sql,
        alias="srv",
        database="app",
        catalog=catalog or Catalog(),
        pii_config=PII,
        codec=CODEC,
        runtime=RUNTIME,
        max_rows=max_rows,
        dialect=SQLSERVER,
    )


def test_cannot_be_constructed_directly() -> None:
    factory = cast(Callable[..., object], ValidatedQuery)
    with pytest.raises(TypeError):
        factory()
    with pytest.raises(TypeError):
        factory(object(), sql="SELECT 1")


def test_cannot_be_copied_or_pickled_into_existence() -> None:
    query = build("SELECT Id FROM Users")
    # pickle.dumps must raise, so nothing is ever unpickled here.
    for clone in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            clone(query)


def test_fields_are_read_only() -> None:
    query = build("SELECT Id FROM Users")
    with pytest.raises(AttributeError):
        query.__setattr__("sql", "DROP TABLE Users")
    assert isinstance(query.parameters, tuple)
    with pytest.raises(TypeError):
        cast(dict[int, object], query.parameters)[0] = 1


def test_token_literals_become_bind_parameters() -> None:
    query = build(f"SELECT Id FROM Users WHERE Email IN ({token('a@b.c')}, {token('d@e.f')})")
    assert query.parameters == ("a@b.c", "d@e.f")
    assert query.sql.count("?") == 2
    assert "pii:v1" not in query.sql
    assert "a@b.c" not in query.sql


def test_injection_payload_stays_a_single_bind_value() -> None:
    query = build(f"SELECT Id FROM Users WHERE Email = {token(INJECTION)}")
    assert query.parameters == (INJECTION,)
    assert "DROP" not in query.sql
    assert "Canary" not in query.sql
    assert query.sql.count(";") == 0


def test_plain_literals_are_not_bound() -> None:
    query = build("SELECT Id FROM Users WHERE Name = 'x' AND Id = 3")
    assert query.parameters == ()
    assert "'x'" in query.sql


def test_generated_sql_reparses_and_passes_the_allowlist() -> None:
    query = build(f"SELECT Id, Email FROM Users WHERE Email = {token('a')} ORDER BY Id")
    reparsed = parse_select(query.sql.replace("?", "'x'"), ParserLimits(65_536, 2000, 8, 500))
    assert isinstance(reparsed, exp.Select)
    validate_allowlist(query.ast, allow_placeholders=True)


def test_ast_property_returns_a_detached_copy() -> None:
    query = build("SELECT Id FROM Users")
    query.ast.set("where", None)
    query.ast.args["expressions"].clear()
    assert query.sql == build("SELECT Id FROM Users").sql


def test_output_plan_records_source_and_protection() -> None:
    query = build("SELECT Email AS Contact, Id, COUNT(*) FROM Users")
    plan = [(o.label, o.kind, o.protected) for o in query.outputs]
    assert plan == [
        ("Contact", "column", True),
        ("Id", "column", False),
        ("column_3", "count", False),
    ]
    assert query.outputs[0].source is not None
    assert query.outputs[0].source.column == "Email"


def test_identity_metadata() -> None:
    query = build("SELECT Id FROM Users", max_rows=17)
    assert (query.alias, query.database, query.max_rows) == ("srv", "app", 17)


@pytest.mark.parametrize(
    ("sql", "max_rows", "expected_top"),
    [
        ("SELECT Id FROM Users", 200, 201),
        ("SELECT TOP 5 Id FROM Users", 200, 5),
        ("SELECT TOP 200 Id FROM Users", 200, 200),
        ("SELECT TOP 201 Id FROM Users", 200, 201),
        ("SELECT TOP 5000 Id FROM Users", 200, 201),
        ("SELECT TOP 0 Id FROM Users", 200, 0),
        ("SELECT Id FROM Users", 1, 2),
        ("SELECT Id FROM Users", 1000, 1001),
    ],
)
def test_row_cap_is_applied_to_the_ast(sql: str, max_rows: int, expected_top: int) -> None:
    query = build(sql, max_rows=max_rows)
    assert query.sql.upper().startswith(f"SELECT TOP {expected_top} ")


def test_invalid_row_limits_are_rejected() -> None:
    for value, code in [
        (0, ErrorCode.INVALID_ARGUMENT),
        (-1, ErrorCode.INVALID_ARGUMENT),
        (1001, ErrorCode.RESULT_LIMIT_EXCEEDED),
    ]:
        with pytest.raises(DomainError) as info:
            build("SELECT Id FROM Users", max_rows=value)
        assert info.value.code is code


def test_repr_and_str_do_not_reveal_sql_binds_or_tokens() -> None:
    query = build(f"SELECT Email FROM Users WHERE Email = {token('secret@example.com')}")
    for text in (repr(query), str(query)):
        assert "secret@example.com" not in text
        assert "pii:v1" not in text
        assert "SELECT" not in text


def test_rejected_input_never_reaches_schema_lookup() -> None:
    catalog = Catalog()
    for sql in ["SELECT 1; SELECT 2", "DROP TABLE Users", "", "SELECT Id FROM Users, Users"]:
        with pytest.raises(DomainError):
            build(sql, catalog=catalog)
    assert catalog.lookups == 0


def test_policy_rejection_produces_no_query() -> None:
    with pytest.raises(DomainError) as info:
        build("SELECT Id FROM Users WHERE Email = 'plain@example.com'")
    assert info.value.code is ErrorCode.QUERY_REJECTED


def test_bind_order_follows_the_generated_text_not_the_tree() -> None:
    query = build(
        f"SELECT TOP 5 Id FROM Users WHERE Email = {token('first')} AND Name = 'x' "
        f"AND Email IN ({token('second')}, {token('third')})"
    )
    assert query.parameters == ("first", "second", "third")
    assert query.sql.count("?") == 3


def test_colons_and_marker_like_text_in_plain_literals_are_not_binds() -> None:
    query = build(
        f"SELECT Id FROM Users WHERE Name = 'a :pii_0 ? __bind_x__' AND Email = {token('v')}"
    )
    assert query.parameters == ("v",)
    assert "'a :pii_0 ? __bind_x__'" in query.sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT /* c1 */ Id FROM /* c2 */ Users -- c3",
        "SELECT Id -- x */ ; DROP TABLE Canary; --\nFROM Users",
        "/* lead */ SELECT Id FROM Users WHERE Name = 'x' /* tail */",
    ],
)
def test_user_comments_never_reach_the_generated_sql(sql: str) -> None:
    query = build(sql)
    assert "/*" not in query.sql
    assert "*/" not in query.sql
    assert "--" not in query.sql
    assert query.sql == build(re.sub(r"/\*.*?\*/|--[^\n]*", " ", sql, flags=re.S)).sql
