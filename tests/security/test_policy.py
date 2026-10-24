from collections.abc import Sequence
from datetime import date, datetime
from decimal import Decimal
from typing import ClassVar

import pytest
from sqlglot import exp
from typed_columns import typed

from sql_safe_mcp.config import PiiConfig, PiiRule, PiiScopeRule
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import SQLSERVER
from sql_safe_mcp.security.lineage import SourceColumn, analyze_query
from sql_safe_mcp.security.parser import ParserLimits, parse_select
from sql_safe_mcp.security.policy import PiiPolicy, PolicyDecision
from sql_safe_mcp.security.reasons import Reason
from sql_safe_mcp.security.schema import ColumnSchema, TypeClass, resolve_tables
from sql_safe_mcp.security.tokens import TokenCodec

LIMITS = ParserLimits(4096, 500, 4, 10)
KEY = bytes(range(32))
CODEC = TokenCodec("srv", KEY)
FOREIGN = TokenCodec("other", KEY)

CONFIG = PiiConfig(
    rules=[
        PiiRule(database="*", schema="dbo", table="Users", columns=["Email", "Phone"]),
        PiiRule(database="sales", table="Orders", columns=["Total"]),
    ]
)


class Catalog:
    tables: ClassVar[dict[tuple[str, str], list[str]]] = {
        ("dbo", "Users"): ["Id", "Email", "Phone", "Name"],
        ("dbo", "Contacts"): ["Id", "Email"],
        ("dbo", "Orders"): ["Id", "UserId", "Total"],
    }

    def list_tables(self) -> list[tuple[str, str]]:
        return list(self.tables)

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        return typed(self.tables[(schema, table)])


def token(value: object, codec: TokenCodec = CODEC) -> str:
    return f"'{codec.encrypt(value)}'"


def evaluate(sql: str, database: str = "sales", codec: TokenCodec = CODEC) -> PolicyDecision:
    query = parse_select(sql, LIMITS)
    analyzed = analyze_query(query, resolve_tables(query, Catalog()), LIMITS, SQLSERVER)
    return PiiPolicy(database, CONFIG, codec).evaluate(analyzed)


def rejected(
    sql: str,
    code: ErrorCode = ErrorCode.QUERY_REJECTED,
    database: str = "sales",
    codec: TokenCodec = CODEC,
) -> None:
    with pytest.raises(DomainError) as info:
        evaluate(sql, database, codec)
    assert info.value.code is code


ALLOWED = {
    "direct projection": "SELECT Email FROM Users",
    "projection with alias": "SELECT Email AS Contact FROM Users",
    "star": "SELECT * FROM Users",
    "qualified star": "SELECT u.* FROM Users u",
    "token equality": f"SELECT Id FROM Users WHERE Email = {token('a@b.c')}",
    "token in list": f"SELECT Id FROM Users WHERE Phone IN ({token('1')}, {token('2')})",
    "token predicate under and/or": (
        f"SELECT Id FROM Users WHERE (Email = {token('a')} OR Phone = {token('b')}) AND Id > 1"
    ),
    "token predicate with count": f"SELECT COUNT(*) FROM Users WHERE Email = {token('a')}",
    "token predicate and projection": f"SELECT Email FROM Users WHERE Email = {token('a')}",
    "protected column in joined table": (
        "SELECT o.Id, u.Email FROM Orders o JOIN Users u ON o.UserId = u.Id"
    ),
    "unprotected same-named column": "SELECT c.Email FROM Contacts c",
    "plain predicate on unprotected column": "SELECT Id FROM Users WHERE Name = 'x'",
}

REJECTED = {
    "plaintext equality": "SELECT Id FROM Users WHERE Email = 'a@b.c'",
    "plaintext in list": "SELECT Id FROM Users WHERE Email IN ('a@b.c')",
    "mixed in list": f"SELECT Id FROM Users WHERE Email IN ({token('a')}, 'plain')",
    "numeric equality": "SELECT Id FROM Users WHERE Phone = 5",
    "not equal token": f"SELECT Id FROM Users WHERE Email <> {token('a')}",
    "greater than token": f"SELECT Id FROM Users WHERE Email > {token('a')}",
    "is null": "SELECT Id FROM Users WHERE Email IS NULL",
    "token on the left": f"SELECT Id FROM Users WHERE {token('a')} = Email",
    "column compared to column": "SELECT Id FROM Users WHERE Email = Name",
    "protected on the right": "SELECT Id FROM Users WHERE Name = Email",
    "join key": "SELECT o.Id FROM Orders o JOIN Users u ON u.Email = o.Total",
    "join predicate token": (
        f"SELECT o.Id FROM Orders o JOIN Users u ON o.UserId = u.Id AND u.Email = {token('a')}"
    ),
    "order by": "SELECT Id FROM Users ORDER BY Email",
    "order by alias of protected": "SELECT Email AS Id FROM Users ORDER BY Id",
    "order by qualified": "SELECT u.Id FROM Users u ORDER BY u.Phone",
    "token in unprotected column": f"SELECT Id FROM Users WHERE Name = {token('a')}",
    "token in select list": f"SELECT {token('a')} FROM Users",
    "token compared to unprotected number": f"SELECT Id FROM Users WHERE Id = {token(1)}",
    "integer token against string column": f"SELECT Id FROM Users WHERE Email = {token(1)}",
    "string token against decimal column": f"SELECT Id FROM Orders WHERE Total = {token('1')}",
    "integer token against decimal column": f"SELECT Id FROM Orders WHERE Total = {token(1)}",
    "mixed token types in list": (
        f"SELECT Id FROM Users WHERE Email IN ({token('a')}, {token(1)})"
    ),
}


@pytest.mark.parametrize("sql", ALLOWED.values(), ids=ALLOWED.keys())
def test_allowed(sql: str) -> None:
    evaluate(sql)


@pytest.mark.parametrize("sql", REJECTED.values(), ids=REJECTED.keys())
def test_rejected(sql: str) -> None:
    rejected(sql)


def test_protected_flags_follow_lineage_not_labels() -> None:
    decision = evaluate("SELECT Id AS Email, Email AS Id, Name FROM Users")
    assert decision.protected == (False, True, False)


def test_star_marks_every_protected_column() -> None:
    assert evaluate("SELECT * FROM Users").protected == (False, True, True, False)


def test_same_column_name_is_protected_only_for_the_configured_table() -> None:
    decision = evaluate("SELECT u.Email, c.Email FROM Users u JOIN Contacts c ON u.Id = c.Id")
    assert decision.protected == (True, False)


def test_count_and_literals_are_never_protected() -> None:
    assert evaluate("SELECT COUNT(*), 1 FROM Users").protected == (False, False)


def test_database_rule_matches_exact_database_only() -> None:
    assert evaluate("SELECT Total FROM Orders", database="sales").protected == (True,)
    assert evaluate("SELECT Total FROM Orders", database="SALES").protected == (True,)
    assert evaluate("SELECT Total FROM Orders", database="other").protected == (False,)


def test_wildcard_database_rule_matches_any_database() -> None:
    assert evaluate("SELECT Email FROM Users", database="anything").protected == (True,)


def test_rule_without_schema_matches_every_schema() -> None:
    config = PiiConfig(rules=[PiiRule(database="*", table="Contacts", columns=["Email"])])
    query = parse_select("SELECT Email FROM Contacts", LIMITS)
    analyzed = analyze_query(query, resolve_tables(query, Catalog()), LIMITS, SQLSERVER)
    assert PiiPolicy("d", config, CODEC).evaluate(analyzed).protected == (True,)


def test_rule_matching_is_case_insensitive() -> None:
    config = PiiConfig(
        rules=[PiiRule(database="*", schema="DBO", table="USERS", columns=["EMAIL"])]
    )
    query = parse_select("SELECT email FROM users", LIMITS)
    analyzed = analyze_query(query, resolve_tables(query, Catalog()), LIMITS, SQLSERVER)
    assert PiiPolicy("d", config, CODEC).evaluate(analyzed).protected == (True,)


@pytest.mark.parametrize(
    ("pattern", "matching_table", "other_table"),
    [
        ("User*", "Users", "Account"),
        ("User?", "Users", "User12"),
        ("User[rs]", "Users", "Userx"),
        ("User[a-z]", "Users", "User1"),
        ("User[!a-r]", "Users", "Userr"),
        ("User[*]", "User*", "Users"),
        ("User[?]", "User?", "Users"),
        ("User[[]", "User[", "Users"),
        ("User[]]", "User]", "Users"),
    ],
)
def test_table_patterns_are_case_insensitive_full_matches(
    pattern: str, matching_table: str, other_table: str
) -> None:
    policy = PiiPolicy(
        "APP",
        PiiConfig(rules=[PiiRule(database="app", table=pattern, columns=["EMAIL"])]),
        CODEC,
    )

    assert policy.is_protected(SourceColumn("dbo", matching_table.lower(), "email"))
    assert not policy.is_protected(SourceColumn("dbo", other_table, "email"))
    assert not policy.is_protected(SourceColumn("dbo", matching_table, "phone"))


def test_token_sites_carry_decrypted_values_without_exposing_them_in_repr() -> None:
    decision = evaluate(
        f"SELECT Id FROM Users WHERE Phone IN ({token('555-0100')}, {token('555-0101')})"
    )
    assert [site.value for site in decision.token_sites] == ["555-0100", "555-0101"]
    assert all(isinstance(site.literal, exp.Literal) for site in decision.token_sites)
    assert "555-0100" not in repr(decision)


def test_foreign_alias_token_is_an_invalid_token() -> None:
    rejected(
        f"SELECT Id FROM Users WHERE Email = {token('a', FOREIGN)}",
        ErrorCode.INVALID_PII_TOKEN,
    )


@pytest.mark.parametrize("bad", ["'pii:v1:AAAA'", "'pii:v1:'", "'pii:v1:" + "A" * 200 + "'"])
def test_malformed_token_is_an_invalid_token(bad: str) -> None:
    rejected(f"SELECT Id FROM Users WHERE Email = {bad}", ErrorCode.INVALID_PII_TOKEN)
    rejected(f"SELECT Id FROM Users WHERE Email IN ({bad})", ErrorCode.INVALID_PII_TOKEN)


def test_policy_does_not_touch_the_query() -> None:
    sql = f"SELECT Id FROM Users WHERE Email = {token('a')}"
    query = parse_select(sql, LIMITS)
    analyzed = analyze_query(query, resolve_tables(query, Catalog()), LIMITS, SQLSERVER)
    before = analyzed.query.sql("tsql")
    PiiPolicy("d", CONFIG, CODEC).evaluate(analyzed)
    assert analyzed.query.sql("tsql") == before


TYPED_CONFIG = PiiConfig(
    rules=[
        PiiRule(
            database="*",
            schema="dbo",
            table="Facts",
            columns=["Visits", "Amount", "Seen", "Blob", "Note"],
        )
    ]
)
TYPED_COLUMNS: dict[str, TypeClass] = {
    "Id": "integer",
    "Visits": "integer",
    "Amount": "decimal",
    "Seen": "datetime",
    "Blob": "binary",
    "Note": "other",
}


class TypedCatalog:
    def list_tables(self) -> list[tuple[str, str]]:
        return [("dbo", "Facts")]

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        return [ColumnSchema(name, kind) for name, kind in TYPED_COLUMNS.items()]


def evaluate_typed(sql: str) -> PolicyDecision:
    query = parse_select(sql, LIMITS)
    analyzed = analyze_query(query, resolve_tables(query, TypedCatalog()), LIMITS, SQLSERVER)
    return PiiPolicy("sales", TYPED_CONFIG, CODEC).evaluate(analyzed)


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("Visits", 7),
        ("Amount", Decimal("1.50")),
        ("Seen", datetime(2026, 1, 2, 3, 4, 5)),
        ("Blob", b"ab"),
    ],
)
def test_token_of_the_column_type_is_accepted(column: str, value: object) -> None:
    decision = evaluate_typed(f"SELECT Id FROM Facts WHERE {column} = {token(value)}")
    assert [site.value for site in decision.token_sites] == [value]


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("Visits", "7"),
        ("Visits", Decimal("7")),
        ("Visits", 7.0),
        ("Visits", True),
        ("Amount", 7),
        ("Amount", "1.50"),
        ("Amount", 1.5),
        ("Seen", date(2026, 1, 2)),
        ("Blob", "00"),
        ("Note", "anything"),
        ("Note", 1),
    ],
)
def test_token_of_another_type_is_rejected(column: str, value: object) -> None:
    with pytest.raises(DomainError) as info:
        evaluate_typed(f"SELECT Id FROM Facts WHERE {column} = {token(value)}")
    assert info.value.code is ErrorCode.QUERY_REJECTED
    assert str(Reason.TOKEN_TYPE_MISMATCH.value) in str(info.value)


def test_forged_token_keeps_priority_over_the_type_check() -> None:
    with pytest.raises(DomainError) as info:
        evaluate_typed(f"SELECT Id FROM Facts WHERE Visits = {token(7, FOREIGN)}")
    assert info.value.code is ErrorCode.INVALID_PII_TOKEN


DENY_CONFIG = PiiConfig(
    mode="deny-by-default",
    exposed_columns=[PiiScopeRule(table="Users", columns=["Id"])],
    deny=[
        PiiScopeRule(table="Contacts", columns=["*"]),
        PiiScopeRule(table="Users", columns=["Phone"]),
    ],
)


def evaluate_deny(sql: str, config: PiiConfig = DENY_CONFIG) -> PolicyDecision:
    query = parse_select(sql, LIMITS)
    analyzed = analyze_query(query, resolve_tables(query, Catalog()), LIMITS, SQLSERVER)
    return PiiPolicy("sales", config, CODEC).evaluate(analyzed)


def test_deny_by_default_protects_unlisted_and_exposes_listed_columns() -> None:
    assert evaluate_deny("SELECT Id, Email, Name FROM Users").protected == (False, True, True)
    assert evaluate_deny("SELECT Total FROM Orders").protected == (True,)


def test_deny_by_default_star_tokenizes_unlisted_columns() -> None:
    decision = evaluate_deny(
        "SELECT * FROM Users",
        PiiConfig(
            mode="deny-by-default", exposed_columns=[PiiScopeRule(table="Users", columns=["Id"])]
        ),
    )
    assert decision.protected == (False, True, True, True)


def test_protect_mode_ignores_exposed_columns() -> None:
    config = PiiConfig(
        rules=[PiiRule(database="*", table="Users", columns=["Email"])],
        exposed_columns=[PiiScopeRule(table="Users", columns=["Email"])],
    )
    assert evaluate_deny("SELECT Email FROM Users", config).protected == (True,)


def test_exposed_columns_match_database_schema_and_table_pattern() -> None:
    config = PiiConfig(
        mode="deny-by-default",
        exposed_columns=[
            PiiScopeRule(database="other", schema="dbo", table="Us*", columns=["Name"])
        ],
    )
    assert evaluate_deny("SELECT Name FROM Users", config).protected == (True,)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT Phone FROM Users",
        "SELECT Phone AS p FROM Users",
        "SELECT Id FROM Users WHERE Phone = 'x'",
        "SELECT Id FROM Users ORDER BY Phone",
        "SELECT u.Id FROM Users u JOIN Contacts c ON c.Id = u.Id",
        "SELECT * FROM Users",
        "SELECT u.* FROM Users u",
        "SELECT * FROM Contacts",
        "SELECT Id FROM Contacts WHERE Id = 1",
    ],
)
def test_denied_column_is_rejected_in_every_position(sql: str) -> None:
    with pytest.raises(DomainError) as info:
        evaluate_deny(sql)
    assert info.value.code is ErrorCode.QUERY_REJECTED
    assert Reason.COLUMN_DENIED.value in info.value.public_message


def test_deny_takes_priority_over_protection_rules() -> None:
    config = PiiConfig(
        rules=[PiiRule(database="*", table="Users", columns=["Email"])],
        deny=[PiiScopeRule(table="Users", columns=["Email"])],
    )
    with pytest.raises(DomainError) as info:
        evaluate_deny("SELECT Email FROM Users", config)
    assert Reason.COLUMN_DENIED.value in info.value.public_message


def test_count_star_does_not_reference_denied_columns() -> None:
    assert evaluate_deny("SELECT COUNT(*) FROM Contacts").protected == (False,)
