"""Targeted tests for boundaries that mutation testing showed were under-specified."""

from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from typing import Any

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlglot import exp
from support import KEY, OWN, RUNTIME, Catalog, SpyConnection, SpyResult, validate

import sql_safe_mcp.security.schema as schema_module
import sql_safe_mcp.security.validated_query as vq_module
from sql_safe_mcp.config import PiiConfig, PiiRule
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import SQLSERVER
from sql_safe_mcp.security.executor import execute_validated
from sql_safe_mcp.security.lineage import _cross_check, analyze_query
from sql_safe_mcp.security.parser import (
    ParserLimits,
    parse_select,
    strip_comments,
    validate_allowlist,
)
from sql_safe_mcp.security.policy import PiiPolicy, PolicyDecision
from sql_safe_mcp.security.reasons import Reason
from sql_safe_mcp.security.schema import (
    ReflectedCatalog,
    SchemaCache,
    TableSchema,
    resolve_tables,
)
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.security.validated_query import issue_validated_query

LIMITS = ParserLimits.from_runtime(RUNTIME)


def analyzed(sql: str):
    query = parse_select(sql, LIMITS)
    return analyze_query(query, resolve_tables(query, Catalog()), LIMITS, SQLSERVER)


# --- validated query ---------------------------------------------------------------------------


def test_output_plan_and_policy_must_have_the_same_length() -> None:
    result = analyzed("SELECT Id, Name FROM Users")
    with pytest.raises(ValueError, match="zip"):
        issue_validated_query(
            result,
            PolicyDecision((False,), ()),
            alias="srv",
            database="app",
            max_rows=5,
            runtime=RUNTIME,
            limits=LIMITS,
        )


def test_a_literal_that_looks_like_a_bind_marker_is_rejected_not_reordered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(vq_module.secrets, "token_hex", lambda _n=None: "0" * 16)
    token = OWN.encrypt("value")
    sql = f"SELECT Id FROM Users WHERE Name = '__bind_{'0' * 16}_0__' AND Email = '{token}'"
    with pytest.raises(DomainError) as info:
        validate(sql)
    assert info.value.public_message == f"Query rejected: {Reason.BIND_UNSAFE.value}."


def test_marker_text_for_a_missing_nonce_is_just_a_literal() -> None:
    token = OWN.encrypt("value")
    query = validate(f"SELECT Id FROM Users WHERE Name = '__bind_None_0__' AND Email = '{token}'")
    assert query.parameters == ("value",)
    assert "'__bind_None_0__'" in query.sql


def test_bind_markers_use_a_fresh_random_nonce_each_time(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[int] = []
    real = vq_module.secrets.token_hex

    def spy(nbytes: int | None = None) -> str:
        seen.append(-1 if nbytes is None else nbytes)
        return real(nbytes)

    monkeypatch.setattr(vq_module.secrets, "token_hex", spy)
    validate(f"SELECT Id FROM Users WHERE Email = '{OWN.encrypt('a')}'")
    assert seen == [8]


# --- executor ----------------------------------------------------------------------------------


def test_rows_must_match_the_output_plan_width() -> None:
    query = validate("SELECT Id FROM Users")
    connection = SpyConnection(SpyResult(["Id"], [(1, 2)]))
    with pytest.raises(ValueError, match="zip"):
        execute_validated(connection, query, OWN)


# --- tokens ------------------------------------------------------------------------------------


def _forge(payload: dict[str, Any] | bytes) -> str:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    nonce = bytes(12)
    sealed = AESGCM(KEY).encrypt(nonce, body, b"pii:v1\x00srv")
    return "pii:v1:" + base64.urlsafe_b64encode(nonce + sealed).decode().rstrip("=")


@pytest.mark.parametrize(
    ("tag", "data"),
    [
        ("decimal", "NaN"),
        ("decimal", "Infinity"),
        ("decimal", "1.50e0"),
        ("decimal", " 1"),
        ("date", "20240229"),
        ("time", "010203"),
        ("datetime", "2024-02-29 13:14:15"),
        ("uuid", "12345678123456781234567812345678"),
        ("uuid", "{12345678-1234-5678-1234-567812345678}"),
        ("bytes", "AP8"),
        ("bytes", "AP8=\n"),
        ("float", 1),
        ("int", 1.0),
        ("bool", 0),
        ("str", 1),
    ],
)
def test_forged_non_canonical_payloads_are_rejected(tag: str, data: Any) -> None:
    token = _forge({"v": 1, "t": tag, "d": data})
    with pytest.raises(DomainError) as info:
        OWN.decrypt(token)
    assert info.value.code is ErrorCode.INVALID_PII_TOKEN


def test_forged_canonical_payloads_round_trip() -> None:
    assert OWN.decrypt(_forge({"v": 1, "t": "decimal", "d": "1.50"})) == OWN.decrypt(
        OWN.encrypt(__import__("decimal").Decimal("1.50"))
    )


def test_a_bool_is_not_accepted_as_a_version_number() -> None:
    with pytest.raises(DomainError):
        OWN.decrypt(_forge({"v": True, "t": "str", "d": "x"}))


def test_short_ciphertext_and_empty_input_are_invalid() -> None:
    codec = TokenCodec("srv", KEY)
    for candidate in ("pii:v1:" + "A" * 27, "pii:v1:" + "A" * 43, ""):
        with pytest.raises(DomainError):
            codec.decrypt(candidate)


# --- schema cache and catalog ------------------------------------------------------------------


def test_cache_entry_expires_exactly_at_the_ttl() -> None:
    now = [0.0]
    cache = SchemaCache(4, 10.0, clock=lambda: now[0])
    cache.put("k", ("v",))
    now[0] = 10.0
    assert cache.get("k") is None


def test_cache_recency_is_refreshed_by_reads_and_overwrites() -> None:
    cache = SchemaCache(2, 1000.0)
    cache.put("a", (1,))
    cache.put("b", (2,))
    cache.put("a", (3,))
    cache.put("c", (4,))
    assert cache.get("b") is None
    assert cache.get("a") == (3,)


class StubInspector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    def get_columns(self, table: str, schema: str | None = None) -> list[dict[str, str]]:
        self.calls.append((table, schema))
        return [{"name": f"{schema}.{table}.c"}]


def test_columns_are_reflected_per_schema_and_cached_per_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = StubInspector()
    monkeypatch.setattr(schema_module, "inspect", lambda _connection: inspector)
    catalog = ReflectedCatalog(
        sa.create_engine("sqlite://").connect(), SchemaCache(8, 60), "a", "d"
    )
    assert catalog.columns("sales", "Items") == ("sales.Items.c",)
    assert catalog.columns("dbo", "Items") == ("dbo.Items.c",)
    assert catalog.columns("sales", "Items") == ("sales.Items.c",)
    assert catalog.columns("sales", "Other") == ("sales.Other.c",)
    assert inspector.calls == [("Items", "sales"), ("Items", "dbo"), ("Other", "sales")]


def test_an_empty_schema_is_reflected_as_the_default_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspector = StubInspector()
    monkeypatch.setattr(schema_module, "inspect", lambda _connection: inspector)
    catalog = ReflectedCatalog(
        sa.create_engine("sqlite://").connect(), SchemaCache(8, 60), "a", "d"
    )
    catalog.columns("", "T")
    assert inspector.calls == [("T", None)]


def test_resolved_schema_and_table_identifiers_are_quoted() -> None:
    query = parse_select("SELECT Id FROM dbo.Users", LIMITS)
    resolve_tables(query, Catalog())
    table = query.find(exp.Table)
    assert table is not None
    assert table.args["db"].args["quoted"] is True
    assert table.this.args["quoted"] is True


def test_a_catalog_qualified_table_node_is_rejected_by_resolution() -> None:
    query = parse_select("SELECT Id FROM Users", LIMITS)
    table = query.find(exp.Table)
    assert table is not None
    table.set("catalog", exp.to_identifier("other"))
    with pytest.raises(DomainError) as info:
        resolve_tables(query, Catalog())
    assert info.value.public_message == f"Query rejected: {Reason.TABLE_SCOPE.value}."


def test_a_non_identifier_table_name_is_rejected_by_resolution() -> None:
    query = parse_select("SELECT Id FROM Users", LIMITS)
    table = query.find(exp.Table)
    assert table is not None
    table.set("this", exp.Var(this="Users"))
    with pytest.raises(DomainError) as info:
        resolve_tables(query, Catalog())
    assert info.value.public_message == f"Query rejected: {Reason.TABLE_SCOPE.value}."


def test_a_vanished_table_is_rejected_when_its_columns_are_loaded() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as connection:
        catalog = ReflectedCatalog(connection, SchemaCache(8, 60), "a", "d")
        with pytest.raises(DomainError) as info:
            catalog.columns("main", "Gone")
    assert info.value.public_message == f"Query rejected: {Reason.TABLE_GONE.value}."


def test_two_case_variants_of_a_table_are_ambiguous() -> None:
    class Twin(Catalog):
        tables = {("dbo", "Users"): ["Id"], ("dbo", "USERS"): ["Id"]}  # noqa: RUF012

    query = parse_select("SELECT Id FROM dbo.users", LIMITS)
    with pytest.raises(DomainError):
        resolve_tables(query, Twin())


# --- lineage -----------------------------------------------------------------------------------


def _tables(*tables: TableSchema) -> Sequence[TableSchema]:
    return tables


USERS = TableSchema("dbo", "Users", ("Id", "Name"))
ORDERS = TableSchema("dbo", "Orders", ("Id", "UserId"))


def test_the_cross_check_accepts_a_fully_resolved_query() -> None:
    query = parse_select("SELECT [Users].[Id] FROM [dbo].[Users]", LIMITS)
    _cross_check(query, _tables(USERS), SQLSERVER)


def test_the_cross_check_rejects_an_unknown_column() -> None:
    query = parse_select("SELECT [Users].[Nope] FROM [dbo].[Users]", LIMITS)
    with pytest.raises(DomainError) as info:
        _cross_check(query, _tables(USERS), SQLSERVER)
    assert info.value.public_message == f"Query rejected: {Reason.QUALIFY_FAILED.value}."


def test_the_cross_check_rejects_a_column_with_the_wrong_case() -> None:
    query = parse_select("SELECT [Users].[id] FROM [dbo].[Users]", LIMITS)
    with pytest.raises(DomainError):
        _cross_check(query, _tables(USERS), SQLSERVER)


def test_the_cross_check_rejects_an_ambiguous_unqualified_column() -> None:
    query = parse_select(
        "SELECT Id FROM [dbo].[Users] JOIN [dbo].[Orders] ON [Orders].[UserId] = [Users].[Id]",
        LIMITS,
    )
    with pytest.raises(DomainError):
        _cross_check(query, _tables(USERS, ORDERS), SQLSERVER)


# --- policy ------------------------------------------------------------------------------------


def _decision(rules: list[PiiRule], sql: str, database: str = "app") -> tuple[bool, ...]:
    return PiiPolicy(database, PiiConfig(rules=rules), OWN).evaluate(analyzed(sql)).protected


def test_a_later_rule_still_applies_after_non_matching_rules() -> None:
    other_db = PiiRule(database="elsewhere", schema="dbo", table="Users", columns=["Name"])
    other_schema = PiiRule(database="*", schema="sales", table="Users", columns=["Name"])
    other_table = PiiRule(database="*", schema="dbo", table="Orders", columns=["Name"])
    other_column = PiiRule(database="*", schema="dbo", table="Users", columns=["Phone"])
    match = PiiRule(database="app", schema="dbo", table="Users", columns=["Name"])
    rules = [other_db, other_schema, other_table, other_column, match]
    assert _decision(rules, "SELECT Id, Name FROM Users") == (False, True)
    assert _decision(rules[:-1], "SELECT Id, Name FROM Users") == (False, False)


def test_a_rule_matches_only_its_own_database_schema_table_and_column() -> None:
    rule = PiiRule(database="app", schema="dbo", table="Users", columns=["Name"])
    assert _decision([rule], "SELECT Name FROM Users", "app") == (True,)
    assert _decision([rule], "SELECT Name FROM Users", "APP") == (True,)
    assert _decision([rule], "SELECT Name FROM Users", "other") == (False,)
    assert _decision([rule], "SELECT Id FROM Users", "app") == (False,)
    assert _decision([rule], "SELECT Id FROM Orders", "app") == (False,)


def test_a_wildcard_rule_column_list_is_case_insensitive() -> None:
    rule = PiiRule(database="*", table="users", columns=["NAME", "id"])
    assert _decision([rule], "SELECT Id, Name FROM Users") == (True, True)


# --- parser ------------------------------------------------------------------------------------


def test_a_hand_built_temp_table_name_is_rejected_by_the_allowlist() -> None:
    for name in ("#t", "@t", "##t"):
        query = exp.select("Id").from_(exp.Table(this=exp.to_identifier(name, quoted=True)))
        with pytest.raises(DomainError) as info:
            validate_allowlist(query)
        assert info.value.public_message == f"Query rejected: {Reason.TABLE_UNSUPPORTED.value}."


def test_strip_comments_clears_every_node_but_keeps_the_tree() -> None:
    query = exp.select("Id").from_("Users")
    for node in query.walk():
        node.add_comments(["c"])
    strip_comments(query)
    assert all(not node.comments for node in query.walk())
    assert query.sql("tsql") == "SELECT Id FROM Users"


def test_generated_sql_never_carries_comments() -> None:
    sql = "/* a */ SELECT /* b */ Id -- c\nFROM Users /* d */"
    assert "/*" not in validate(sql).sql
    assert "--" not in validate(sql).sql


# --- coverage of defensive branches (hand-built ASTs) ------------------------------------------


def _rejected_with(query: exp.Select, reason: Reason) -> None:
    with pytest.raises(DomainError) as info:
        validate_allowlist(query)
    assert info.value.public_message == f"Query rejected: {reason.value}."


def test_a_column_whose_name_is_not_an_identifier_is_rejected() -> None:
    query = exp.select(exp.Column(this=exp.Var(this="x"))).from_("Users")
    _rejected_with(query, Reason.COLUMN_REFERENCE_UNSUPPORTED)


def test_a_star_outside_a_projection_is_rejected() -> None:
    query = exp.Select(expressions=[exp.Alias(this=exp.Star(), alias=exp.to_identifier("x"))])
    _rejected_with(query, Reason.STAR_PROJECTION_ONLY)


def test_a_parenthesized_projection_is_rejected() -> None:
    query = exp.Select(expressions=[exp.Paren(this=exp.column("Id"))]).from_("Users")
    _rejected_with(query, Reason.PROJECTION_UNSUPPORTED)


def test_an_aliased_parenthesized_projection_is_rejected() -> None:
    query = exp.Select(
        expressions=[exp.Alias(this=exp.Paren(this=exp.column("Email")), alias="e")]
    ).from_("Users")
    _rejected_with(query, Reason.PROJECTION_UNSUPPORTED)


def test_an_aliased_comparison_projection_is_rejected() -> None:
    query = exp.Select(
        expressions=[
            exp.Alias(
                this=exp.EQ(this=exp.column("Email"), expression=exp.Literal.string("x")),
                alias="hit",
            )
        ]
    ).from_("Users")
    _rejected_with(query, Reason.PROJECTION_UNSUPPORTED)


def test_lineage_refuses_an_aliased_expression_even_if_the_allowlist_let_it_through() -> None:
    # Defense in depth: the lineage stage must not label an untraceable projection "literal".
    query = exp.Select(
        expressions=[exp.Alias(this=exp.Paren(this=exp.column("Email")), alias="e")]
    ).from_(exp.to_table("Users"))
    schemas = resolve_tables(query, Catalog())
    with pytest.raises(DomainError) as info:
        analyze_query(query, schemas, LIMITS, SQLSERVER)
    assert info.value.public_message == f"Query rejected: {Reason.PROJECTION_UNSUPPORTED.value}."


def test_a_projection_without_a_from_clause_is_accepted() -> None:
    assert validate("SELECT 1, 'x', NULL").sql.startswith("SELECT TOP ")


def test_table_resolution_must_match_the_query_tables() -> None:
    query = parse_select("SELECT Id FROM Users", LIMITS)
    with pytest.raises(DomainError) as info:
        analyze_query(query, (), LIMITS, SQLSERVER)
    assert info.value.public_message == f"Query rejected: {Reason.TABLE_RESOLUTION_MISMATCH.value}."


def test_a_detached_protected_column_is_not_in_a_where_clause() -> None:
    from sql_safe_mcp.security.lineage import AnalyzedQuery, ColumnRef, SourceColumn

    detached = exp.column("Email")
    ref = ColumnRef(detached, SourceColumn("dbo", "Users", "Email"))
    fake = AnalyzedQuery(exp.select("1"), (), (ref,))
    rules = [PiiRule(database="*", table="Users", columns=["Email"])]
    with pytest.raises(DomainError) as info:
        PiiPolicy("app", PiiConfig(rules=rules), OWN).evaluate(fake)
    assert info.value.public_message == f"Query rejected: {Reason.PROTECTED_POSITION.value}."


def test_a_token_prefix_surviving_generation_is_rejected() -> None:
    result = analyzed("SELECT Id FROM Users WHERE Name = 'pii:v1:leak'")
    with pytest.raises(DomainError) as info:
        issue_validated_query(
            result,
            PolicyDecision((False,), ()),
            alias="srv",
            database="app",
            max_rows=5,
            runtime=RUNTIME,
            limits=LIMITS,
        )
    assert info.value.public_message == f"Query rejected: {Reason.TOKEN_NOT_REPLACED.value}."


# --- generated SQL is fully quoted, exact text --------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        (
            "select id, EMAIL from dbo.users u where id = 1",
            "SELECT TOP 201 [u].[Id], [u].[Email] FROM [dbo].[Users] AS u WHERE [u].[Id] = 1",
        ),
        (
            "SELECT * FROM Orders",
            "SELECT TOP 201 [Orders].[Id], [Orders].[UserId], [Orders].[Total] FROM [dbo].[Orders]",
        ),
        (
            "SELECT o.Id FROM Users u JOIN Orders o ON o.UserId = u.Id ORDER BY u.Id DESC",
            "SELECT TOP 201 [o].[Id] FROM [dbo].[Users] AS u JOIN [dbo].[Orders] AS o "
            "ON [o].[UserId] = [u].[Id] ORDER BY [u].[Id] DESC",
        ),
    ],
)
def test_generated_sql_is_exact_and_fully_quoted(sql: str, expected: str) -> None:
    assert validate(sql).sql == expected


def test_a_none_schema_from_reflection_becomes_an_empty_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sql_safe_mcp.models import TableSummary

    monkeypatch.setattr(
        schema_module, "reflect_tables", lambda _connection: [TableSummary(schema=None, name="T")]
    )
    catalog = ReflectedCatalog(
        sa.create_engine("sqlite://").connect(), SchemaCache(8, 60), "a", "d"
    )
    assert catalog.list_tables() == [("", "T")]


# --- policy: positions that only a hand-built tree can reach --------------------------------------


def test_a_bare_protected_column_used_as_a_predicate_is_rejected() -> None:
    rules = [PiiRule(database="*", schema="dbo", table="Users", columns=["Name"])]
    query = parse_select("SELECT Id FROM Users WHERE Name", LIMITS)
    result = analyze_query(query, resolve_tables(query, Catalog()), LIMITS, SQLSERVER)
    with pytest.raises(DomainError) as info:
        PiiPolicy("app", PiiConfig(rules=rules), OWN).evaluate(result)
    assert info.value.public_message == f"Query rejected: {Reason.PROTECTED_POSITION.value}."


def test_a_protected_column_inside_an_in_list_is_not_a_token_comparison() -> None:
    from sql_safe_mcp.security.lineage import AnalyzedQuery, ColumnRef, SourceColumn

    protected = exp.column("Email", table="u")
    other = exp.column("Id", table="u")
    where = exp.Where(this=exp.In(this=other, expressions=[protected]))
    query = exp.select("1")
    query.set("where", where)
    ref = ColumnRef(protected, SourceColumn("dbo", "Users", "Email"))
    rules = [PiiRule(database="*", table="Users", columns=["Email"])]
    with pytest.raises(DomainError) as info:
        PiiPolicy("app", PiiConfig(rules=rules), OWN).evaluate(AnalyzedQuery(query, (), (ref,)))
    assert info.value.public_message == f"Query rejected: {Reason.PROTECTED_POSITION.value}."


def test_a_detached_token_comparison_is_not_inside_a_where_clause() -> None:
    from sql_safe_mcp.security.lineage import AnalyzedQuery, ColumnRef, SourceColumn

    column = exp.column("Email", table="u")
    token = OWN.encrypt("value")
    exp.EQ(this=column, expression=exp.Literal.string(token))
    ref = ColumnRef(column, SourceColumn("dbo", "Users", "Email"))
    rules = [PiiRule(database="*", table="Users", columns=["Email"])]
    with pytest.raises(DomainError) as info:
        PiiPolicy("app", PiiConfig(rules=rules), OWN).evaluate(
            AnalyzedQuery(exp.select("1"), (), (ref,))
        )
    assert info.value.public_message == f"Query rejected: {Reason.PROTECTED_POSITION.value}."


def test_the_allowlist_refuses_a_non_select_root() -> None:
    for root in (
        exp.Delete(this=exp.to_table("t")),
        exp.Union(this=exp.select("1"), expression=exp.select("2")),
        exp.column("a"),
    ):
        with pytest.raises(DomainError) as info:
            validate_allowlist(root)
        assert info.value.public_message == f"Query rejected: {Reason.SELECT_ONLY.value}."
