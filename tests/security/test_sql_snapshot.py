"""Golden snapshot of the SQL generated for every allowlisted query on both dialects.

An SQLGlot upgrade (or a change to quoting, ordering, or the row cap) shows up here as a diff of
the exact text sent to the database. Review the semantics of each changed statement, then
regenerate the snapshot with
`UPDATE_SQL_SNAPSHOT=1 uv run pytest tests/security/test_sql_snapshot.py`.
"""

from __future__ import annotations

import difflib
import json
import os
from collections.abc import Sequence
from pathlib import Path

import pytest
from support import ALIAS, DATABASE, OWN, RUNTIME
from test_allowlist import ALLOWED
from typed_columns import typed

from sql_safe_mcp.config import PiiConfig, PiiRule
from sql_safe_mcp.errors import DomainError
from sql_safe_mcp.security.dialect import MYSQL, SQLSERVER, SqlDialect
from sql_safe_mcp.security.pipeline import validate_sql
from sql_safe_mcp.security.schema import ColumnSchema

SNAPSHOT = Path(__file__).with_name("sql_snapshot.json")
COLUMNS = ["a b", *"abcdefghi", "id"]
TABLES = ("t", "u")
DIALECTS: tuple[SqlDialect, ...] = (SQLSERVER, MYSQL)
# The config requires a rule; this one matches no table, so the snapshot shows plain generation.
_NO_MATCH = PiiConfig(rules=[PiiRule(database="*", schema="dbo", table="Absent", columns=["x"])])


class _Catalog:
    def __init__(self, schema: str) -> None:
        self._schema = schema

    def list_tables(self) -> list[tuple[str, str]]:
        return [(self._schema, table) for table in TABLES]

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        assert (schema, table) in self.list_tables()
        # `u` shares only `id` and `f` with `t`, so unqualified columns in joins stay unambiguous.
        return typed(COLUMNS if table == "t" else ["id", "f"])


def _generate(dialect: SqlDialect) -> dict[str, str]:
    catalog = _Catalog("dbo" if dialect.has_schema else "")
    generated: dict[str, str] = {}
    for sql in ALLOWED.values():
        try:
            query = validate_sql(
                sql,
                alias=ALIAS,
                database=DATABASE,
                catalog=catalog,
                pii_config=_NO_MATCH,
                codec=OWN,
                runtime=RUNTIME,
                max_rows=200,
                dialect=dialect,
            )
        except DomainError:
            if dialect is SQLSERVER:
                raise
            continue  # T-SQL-only syntax (brackets, TOP) is not valid for MySQL
        generated[sql] = query.sql
    return generated


def _current() -> dict[str, dict[str, str]]:
    return {dialect.name: _generate(dialect) for dialect in DIALECTS}


def _dump(snapshot: dict[str, dict[str, str]]) -> str:
    return json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def test_generated_sql_matches_snapshot() -> None:
    actual = _dump(_current())
    if os.environ.get("UPDATE_SQL_SNAPSHOT") == "1":
        SNAPSHOT.write_text(actual, encoding="utf-8", newline="\n")
    expected = SNAPSHOT.read_text(encoding="utf-8")
    if actual != expected:
        diff = "".join(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                actual.splitlines(keepends=True),
                "sql_snapshot.json",
                "generated",
            )
        )
        pytest.fail(
            "Generated SQL changed. Check the semantics of every changed statement "
            "(quoting, ordering, TOP/LIMIT), then update the snapshot with "
            "UPDATE_SQL_SNAPSHOT=1.\n" + diff
        )


def test_snapshot_covers_every_allowed_case_on_tsql() -> None:
    assert len(json.loads(SNAPSHOT.read_text(encoding="utf-8"))["tsql"]) == len(
        set(ALLOWED.values())
    )
