"""One rule matcher serves the policy and the advisory audit; they must agree on coverage."""

from __future__ import annotations

import pytest

from sql_safe_mcp.config import PiiConfig, PiiRule, PiiScopeRule
from sql_safe_mcp.pii_audit import Catalog, _match_columns
from sql_safe_mcp.security.lineage import SourceColumn
from sql_safe_mcp.security.policy import PiiPolicy
from sql_safe_mcp.security.rules import rule_covers_column, rule_matches_table
from sql_safe_mcp.security.tokens import TokenCodec

KEY = bytes(range(32))


def _rule(**fields: object) -> PiiRule:
    return PiiRule.model_validate({"database": "*", "table": "T", "columns": ["c"], **fields})


@pytest.mark.parametrize(
    ("rule", "database", "schema", "table", "expected"),
    [
        (_rule(), "anydb", "dbo", "t", True),
        (_rule(database="Clinic"), "clinic", "dbo", "T", True),
        (_rule(database="clinic"), "other", "dbo", "T", False),
        (_rule(schema="DBO"), "x", "dbo", "T", True),
        (_rule(schema="dbo"), "x", "reporting", "T", False),
        (_rule(schema="dbo"), "x", None, "T", False),
        (_rule(), "x", None, "T", True),
        (_rule(schema=""), "x", None, "T", True),
        (_rule(schema=""), "x", "dbo", "T", False),
        (_rule(table="Pat*"), "x", "dbo", "patients", True),
        (_rule(table="Pat*"), "x", "dbo", "visits", False),
    ],
)
def test_rule_matches_table_follows_the_policy_semantics(
    rule: PiiRule, database: str, schema: str | None, table: str, expected: bool
) -> None:
    assert rule_matches_table(rule, database, schema, table) is expected


@pytest.mark.parametrize(
    ("columns", "column", "expected"),
    [
        (["c"], "C", True),
        (["c"], "d", False),
        (["*"], "anything", True),
    ],
)
def test_rule_covers_column_is_case_insensitive_and_honours_star(
    columns: list[str], column: str, expected: bool
) -> None:
    assert rule_covers_column(_rule(columns=columns), column) is expected


def test_config_rejects_a_star_mixed_with_names() -> None:
    """rule_covers_column matches '*' only as the whole list; config must never allow a mix."""
    with pytest.raises(ValueError):
        PiiConfig(deny=[PiiScopeRule.model_validate({"table": "T", "columns": ["*", "Email"]})])


CATALOG: Catalog = {
    "clinic": [
        ("dbo", "Patients", ("Id", "Mrn", "Email", "Notes")),
        ("reporting", "Patients", ("Id", "Mrn", "Email")),
        (None, "visits", ("visit_id", "notes", "Email")),
    ],
    "Other": [("dbo", "Patients", ("Id", "Email"))],
}

# Config forbids "*" in pii rules, so protection rules list their columns explicitly.
PROTECT_RULES = [
    _rule(table="Patients", columns=["Email"]),
    _rule(database="clinic", schema="dbo", table="Pat*", columns=["Mrn", "id"]),
    _rule(database="clinic", table="vis*", columns=["visit_id", "notes", "Email"]),
    _rule(schema="reporting", table="Patients", columns=["Id", "Mrn"]),
]

DENY_RULES = [
    PiiScopeRule.model_validate({"database": "clinic", "table": "*", "columns": ["Notes"]}),
    PiiScopeRule.model_validate({"database": "clinic", "table": "vis*", "columns": ["notes"]}),
    PiiScopeRule.model_validate({"table": "Patients", "schema": "reporting", "columns": ["*"]}),
]


def _key(database: str, schema: str | None, table: str, name: str) -> tuple[str, str, str, str]:
    return (database.casefold(), (schema or "").casefold(), table.casefold(), name.casefold())


def _columns() -> list[tuple[str, str | None, str, str]]:
    return [
        (database, schema, table, name)
        for database, entries in CATALOG.items()
        for schema, table, names in entries
        for name in names
    ]


def _policy(database: str, config: PiiConfig) -> PiiPolicy:
    codec = TokenCodec("srv", KEY)
    return PiiPolicy(database, config, codec)


def test_audit_coverage_equals_policy_protection() -> None:
    """Fails if the audit and policy paths diverge on a one-sided matcher condition."""
    config = PiiConfig(rules=PROTECT_RULES)

    audit_covered: set[tuple[str, str, str, str]] = set()
    for rule in PROTECT_RULES:
        _, keys = _match_columns(rule, CATALOG)
        audit_covered |= {_key(*key) for key in keys}

    policy_covered = set()
    for database, schema, table, name in _columns():
        policy = _policy(database, config)
        source = SourceColumn(schema or "", table, name)
        if policy.protected_domain(source) is not None:
            policy_covered.add(_key(database, schema, table, name))

    assert audit_covered == policy_covered
    assert audit_covered  # the scenario must actually cover something


def test_audit_deny_coverage_equals_policy_denial() -> None:
    config = PiiConfig(rules=PROTECT_RULES, deny=DENY_RULES)

    audit_denied: set[tuple[str, str, str, str]] = set()
    for rule in DENY_RULES:
        _, keys = _match_columns(rule, CATALOG)
        audit_denied |= {_key(*key) for key in keys}

    policy_denied = set()
    for database, schema, table, name in _columns():
        policy = _policy(database, config)
        if policy.is_denied(SourceColumn(schema or "", table, name)):
            policy_denied.add(_key(database, schema, table, name))

    assert audit_denied == policy_denied
    assert audit_denied  # the scenario must actually deny something


def test_match_columns_counts_every_matching_table_of_a_database() -> None:
    catalog: Catalog = {"clinic": [("dbo", "Patients", ("Email",)), ("dbo", "Visits", ("Email",))]}
    tables, keys = _match_columns(_rule(table="*", columns=["Email"]), catalog)

    assert tables == 2
    assert len(keys) == 2


def test_match_columns_skips_a_table_without_hits_without_stopping_the_scan() -> None:
    catalog: Catalog = {"clinic": [("dbo", "Other", ("Id",)), ("dbo", "Patients", ("Email",))]}
    tables, keys = _match_columns(_rule(table="*", columns=["Email"]), catalog)

    assert tables == 1
    assert keys == {("clinic", "dbo", "Patients", "email")}


def test_match_columns_skips_a_non_matching_table_without_stopping_the_scan() -> None:
    catalog: Catalog = {"clinic": [("dbo", "Visits", ("Email",)), ("dbo", "Patients", ("Email",))]}
    tables, keys = _match_columns(_rule(table="Pat*", columns=["Email"]), catalog)

    assert tables == 1
    assert keys == {("clinic", "dbo", "Patients", "email")}
