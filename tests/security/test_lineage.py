from collections.abc import Sequence
from typing import ClassVar

import pytest
from sqlglot import exp
from typed_columns import typed

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import SQLSERVER
from sql_safe_mcp.security.lineage import AnalyzedQuery, SourceColumn, analyze_query
from sql_safe_mcp.security.parser import ParserLimits, parse_select
from sql_safe_mcp.security.schema import ColumnSchema, resolve_tables

LIMITS = ParserLimits(4096, 500, 4, 10)

USERS = (
    SourceColumn("dbo", "Users", "Id", "integer"),
    SourceColumn("dbo", "Users", "Email", "string"),
)


class Catalog:
    tables: ClassVar[dict[tuple[str, str], list[str]]] = {
        ("dbo", "Users"): ["Id", "Email"],
        ("dbo", "Orders"): ["Id", "UserId", "Total"],
    }

    def list_tables(self) -> list[tuple[str, str]]:
        return list(self.tables)

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        return typed(self.tables[(schema, table)])


def analyze(sql: str, limits: ParserLimits = LIMITS) -> AnalyzedQuery:
    query = parse_select(sql, limits)
    return analyze_query(query, resolve_tables(query, Catalog()), limits, SQLSERVER)


def rejected(sql: str, limits: ParserLimits = LIMITS) -> None:
    with pytest.raises(DomainError) as info:
        analyze(sql, limits)
    assert info.value.code is ErrorCode.QUERY_REJECTED


def labels(result: AnalyzedQuery) -> list[str]:
    return [output.label for output in result.outputs]


def sources(result: AnalyzedQuery) -> list[SourceColumn | None]:
    return [output.source for output in result.outputs]


def test_star_is_expanded_with_lineage() -> None:
    result = analyze("SELECT * FROM dbo.Users")
    assert labels(result) == ["Id", "Email"]
    assert sources(result) == list(USERS)
    assert not list(result.query.find_all(exp.Star))


def test_table_star_and_joined_columns() -> None:
    result = analyze("SELECT u.*, o.Id FROM Users u JOIN Orders o ON u.Id = o.UserId")
    assert labels(result) == ["Id", "Email", "Id"]
    assert sources(result) == [*USERS, SourceColumn("dbo", "Orders", "Id", "integer")]


def test_bare_star_expands_every_table_in_order() -> None:
    result = analyze("SELECT * FROM Users u JOIN Orders o ON u.Id = o.UserId")
    assert [source.table for source in sources(result) if source] == ["Users"] * 2 + ["Orders"] * 3


def test_alias_changes_label_not_lineage() -> None:
    result = analyze("SELECT email AS Contact FROM users")
    assert labels(result) == ["Contact"]
    assert sources(result) == [SourceColumn("dbo", "Users", "Email", "string")]


def test_swapped_aliases_follow_lineage() -> None:
    result = analyze("SELECT Id AS Email, Email AS Id FROM Users")
    assert labels(result) == ["Email", "Id"]
    assert sources(result) == list(USERS)


def test_duplicate_labels_keep_positional_lineage() -> None:
    result = analyze("SELECT u.Id, o.Id FROM Users u JOIN Orders o ON u.Id = o.UserId")
    assert labels(result) == ["Id", "Id"]
    assert sources(result) == [USERS[0], SourceColumn("dbo", "Orders", "Id", "integer")]


def test_count_and_literals_have_no_source() -> None:
    result = analyze("SELECT COUNT(*), 1, NULL AS n FROM Users")
    assert [output.kind for output in result.outputs] == ["count", "literal", "literal"]
    assert sources(result) == [None, None, None]
    assert labels(result)[2] == "n"
    assert labels(result)[:2] == ["column_1", "column_2"]


def test_columns_are_rewritten_to_reflected_names() -> None:
    result = analyze("SELECT EMAIL FROM DBO.USERS WHERE id = 1")
    columns = [(column.table, column.name) for column in result.query.find_all(exp.Column)]
    assert columns == [("Users", "Email"), ("Users", "Id")]


def test_every_column_reference_has_lineage() -> None:
    result = analyze(
        "SELECT u.Email FROM Users u JOIN Orders o ON u.Id = o.UserId "
        "WHERE o.Total > 1 ORDER BY u.Id"
    )
    assert [ref.source.column for ref in result.references] == [
        "Email",
        "Id",
        "UserId",
        "Total",
        "Id",
    ]
    assert all(isinstance(ref.node, exp.Column) for ref in result.references)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT nope FROM Users",
        "SELECT Id FROM Users u JOIN Orders o ON u.Id = o.UserId",
        "SELECT x.Id FROM Users u",
        "SELECT Users.Id FROM Users u",
        "SELECT x.* FROM Users u",
        "SELECT * FROM Users JOIN Users ON 1 = 1",
        "SELECT a.Id FROM Users a JOIN Orders A ON 1 = 1",
        "SELECT Id FROM Users WHERE Missing = 1",
        "SELECT o.Id FROM Users u JOIN Orders o ON u.Nope = o.UserId",
    ],
)
def test_unknown_or_ambiguous_references_are_rejected(sql: str) -> None:
    rejected(sql)


def test_order_by_alias_uses_the_projected_lineage() -> None:
    result = analyze("SELECT Email AS Id FROM Users ORDER BY Id")
    order_ref = result.references[-1]
    assert order_ref.source == SourceColumn("dbo", "Users", "Email", "string")


def test_order_by_qualified_column_ignores_aliases() -> None:
    result = analyze("SELECT Email AS Id FROM Users ORDER BY Users.Id")
    assert result.references[-1].source == SourceColumn("dbo", "Users", "Id", "integer")


def test_order_by_ambiguous_alias_is_rejected() -> None:
    rejected("SELECT Id AS Email, Email FROM Users ORDER BY Email")


def test_order_by_alias_of_non_column_is_rejected() -> None:
    rejected("SELECT COUNT(*) AS n FROM Users ORDER BY n")


def test_limits_are_rechecked_after_star_expansion() -> None:
    sql = "SELECT * FROM Orders"
    nodes = len(list(parse_select(sql, LIMITS).walk()))
    rejected(sql, ParserLimits(4096, nodes + 1, 4, 10))
    analyze(sql, ParserLimits(4096, 500, 4, 10))


def test_input_query_is_not_mutated() -> None:
    query = parse_select("SELECT * FROM Users", LIMITS)
    tables = resolve_tables(query, Catalog())
    before = query.sql("tsql")
    analyze_query(query, tables, LIMITS, SQLSERVER)
    assert query.sql("tsql") == before


def test_result_query_passes_the_allowlist_again() -> None:
    from sql_safe_mcp.security.parser import validate_allowlist

    validate_allowlist(analyze("SELECT * FROM Users WHERE Id IN (1, 2)").query)


def test_order_by_alias_with_self_join_uses_the_projected_binding() -> None:
    result = analyze("SELECT b.Email AS Id FROM Users a JOIN Users b ON a.Id = b.Id ORDER BY Id")
    assert result.references[-1].node.table == "b"
