from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase

from sqlalchemy import inspect
from sqlalchemy.exc import NoSuchTableError

from sql_safe_mcp.config import AppConfig, PiiRule, ServerConfig
from sql_safe_mcp.db.extras import extras_for
from sql_safe_mcp.db.reflection import list_tables
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.diagnostics import describe_error, secrets_for

# Name fragments the advisor flags on unprotected columns. A heuristic, not a guarantee.
SUSPICIOUS_NAME_PARTS: tuple[str, ...] = (
    "email",
    "phone",
    "mobile",
    "ssn",
    "passport",
    "dob",
    "birth",
    "address",
    "zip",
    "postal",
    "name",
    "diagnos",
    "icd",
    "mrn",
    "guardian",
    "ip_",
    "device",
    "photo",
    "notes",
)

# database -> [(schema, table, column names)]
type TableColumns = tuple[str | None, str, tuple[str, ...]]
type Catalog = Mapping[str, Sequence[TableColumns]]
type CatalogCollector = Callable[[AppConfig, str], Catalog]


class CatalogError(Exception):
    """A database could not be reflected; carries only a log-safe description."""


@dataclass(frozen=True, slots=True)
class AuditReport:
    lines: tuple[str, ...]
    unmatched_rules: int
    errors: int


def _database_names(rules: Sequence[PiiRule]) -> tuple[set[str], bool]:
    explicit = {rule.database for rule in rules if rule.database != "*"}
    return explicit, any(rule.database == "*" for rule in rules)


def collect_catalog(config: AppConfig, alias: str) -> Catalog:
    """Reflect every database named by the alias's rules; ``*`` means every visible database."""
    server = config.servers[alias]
    assert server.pii is not None
    explicit, wildcard = _database_names(server.pii.rules)
    registry = EngineRegistry(config)
    secrets = secrets_for(server.connection_url.get_secret_value(), alias)
    try:
        names = set(explicit)
        if wildcard:
            try:
                with registry.get(alias, None).connect() as connection:
                    names.update(extras_for(server.engine).list_databases(connection))
            except Exception as exc:
                raise CatalogError(
                    f"cannot list databases: {describe_error(exc, secrets, include_message=False)}"
                ) from None
        catalog: dict[str, list[TableColumns]] = {}
        for database in sorted(names, key=str.casefold):
            try:
                with registry.get(alias, database).connect() as connection:
                    inspector = inspect(connection)
                    entries: list[TableColumns] = []
                    for table in list_tables(connection):
                        try:
                            columns = inspector.get_columns(table.name, schema=table.schema_)
                        except NoSuchTableError:
                            # Listed but gone before reflection (temporary tables in tempdb).
                            continue
                        entries.append(
                            (
                                table.schema_,
                                table.name,
                                tuple(str(item["name"]) for item in columns),
                            )
                        )
                    catalog[database] = entries
            except Exception as exc:
                raise CatalogError(
                    f"cannot reflect database {database!r}: "
                    f"{describe_error(exc, secrets, include_message=False)}"
                ) from None
        return catalog
    finally:
        registry.dispose()


def _rule_matches(rule: PiiRule, database: str, schema: str | None, table: str) -> bool:
    if rule.database != "*" and rule.database.casefold() != database.casefold():
        return False
    if rule.schema_ is not None and rule.schema_.casefold() != (schema or "").casefold():
        return False
    return fnmatchcase(table.casefold(), rule.table.casefold())


def _describe(rule: PiiRule) -> str:
    schema = f"{rule.schema_}." if rule.schema_ else ""
    return f"{rule.database}.{schema}{rule.table}({', '.join(rule.columns)})"


def audit_server(alias: str, server: ServerConfig, catalog: Catalog) -> AuditReport:
    """Per-rule match counts and a name-based advisor for columns no rule protects."""
    assert server.pii is not None
    lines: list[str] = []
    unmatched = 0
    protected: set[tuple[str, str | None, str, str]] = set()
    for rule in server.pii.rules:
        wanted = {column.casefold() for column in rule.columns}
        tables = columns = 0
        for database, entries in catalog.items():
            for schema, table, names in entries:
                if not _rule_matches(rule, database, schema, table):
                    continue
                hits = [name for name in names if name.casefold() in wanted]
                if not hits:
                    continue
                tables += 1
                columns += len(hits)
                protected.update((database, schema, table, name.casefold()) for name in hits)
        if tables == 0:
            unmatched += 1
            lines.append(f"WARNING: {alias}: rule {_describe(rule)} matches no table or column")
        else:
            lines.append(
                f"{alias}: rule {_describe(rule)} matched {tables} table(s), {columns} column(s)"
            )
    for database, entries in catalog.items():
        for schema, table, names in entries:
            for name in names:
                folded = name.casefold()
                if (database, schema, table, folded) in protected:
                    continue
                if any(part in folded for part in SUSPICIOUS_NAME_PARTS):
                    qualified = ".".join(part for part in (database, schema, table, name) if part)
                    lines.append(
                        f"WARNING: {alias}: unprotected column looks personal: {qualified}"
                    )
    return AuditReport(tuple(lines), unmatched, 0)


def verify_pii_rules(config: AppConfig, collect: CatalogCollector = collect_catalog) -> AuditReport:
    lines: list[str] = []
    unmatched = errors = 0
    for alias, server in config.servers.items():
        if server.access_level != "all_pii_safe":
            continue
        try:
            catalog = collect(config, alias)
        except CatalogError as exc:
            errors += 1
            lines.append(f"ERROR: {alias}: {exc}")
            continue
        report = audit_server(alias, server, catalog)
        lines.extend(report.lines)
        unmatched += report.unmatched_rules
    if not lines:
        lines.append("No all_pii_safe server aliases to verify.")
    return AuditReport(tuple(lines), unmatched, errors)
