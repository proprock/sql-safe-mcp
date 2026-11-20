"""The one place where a PII rule decides whether it covers a table and a column.

Both the query policy (`PiiPolicy`) and the advisory audit (`pii_audit`) call these functions, so
they cannot drift apart. Matching is case-insensitive; the table name is a glob (`fnmatchcase`).
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from sql_safe_mcp.config import PiiRule


def rule_matches_table(rule: PiiRule, database: str, schema: str | None, table: str) -> bool:
    """Whether the rule's database, schema, and table pattern cover the given table.

    A rule without a schema covers every schema; a missing table schema is compared as ``""``.
    """
    if rule.database != "*" and rule.database.casefold() != database.casefold():
        return False
    if rule.schema_ is not None and rule.schema_.casefold() != (schema or "").casefold():
        return False
    return fnmatchcase(table.casefold(), rule.table.casefold())


def rule_covers_column(rule: PiiRule, column: str) -> bool:
    """Whether the rule's column list covers the column; ``["*"]`` covers every column."""
    if rule.columns == ["*"]:
        return True
    return column.casefold() in {item.casefold() for item in rule.columns}
