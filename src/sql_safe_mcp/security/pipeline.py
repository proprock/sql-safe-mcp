from __future__ import annotations

from sql_safe_mcp.config import PiiConfig, RuntimeConfig
from sql_safe_mcp.security.dialect import SqlDialect
from sql_safe_mcp.security.lineage import analyze_query
from sql_safe_mcp.security.parser import ParserLimits, parse_select
from sql_safe_mcp.security.policy import PiiPolicy
from sql_safe_mcp.security.schema import TableCatalog, resolve_tables
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.security.validated_query import ValidatedQuery, issue_validated_query


def validate_sql(
    sql: str,
    *,
    alias: str,
    database: str,
    catalog: TableCatalog,
    pii_config: PiiConfig,
    codec: TokenCodec,
    runtime: RuntimeConfig,
    max_rows: int,
    dialect: SqlDialect,
) -> ValidatedQuery:
    """Run caller SQL through parse, allowlist, reflection, lineage, and PII policy.

    Any rejection raises a DomainError before the catalog or database is used further.
    """
    limits = ParserLimits.from_runtime(runtime)
    query = parse_select(sql, limits, dialect)
    tables = resolve_tables(query, catalog, dialect)
    analyzed = analyze_query(query, tables, limits, dialect)
    decision = PiiPolicy(database, pii_config, codec).evaluate(analyzed)
    return issue_validated_query(
        analyzed,
        decision,
        alias=alias,
        database=database,
        max_rows=max_rows,
        runtime=runtime,
        limits=limits,
        dialect=dialect,
        tables=tuple((table.schema, table.name) for table in tables),
    )
