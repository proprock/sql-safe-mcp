"""A starting `pii` section for a deny-by-default alias, drafted from the reflected schema.

The draft is a suggestion for an operator to review, never a decision. It reads names and types
only (no rows) and prints names only: every object name comes from database metadata and is
untrusted, so data goes through ``yaml.safe_dump`` and names in comments through ``log_field``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

import yaml
from sqlalchemy import Connection, inspect
from sqlalchemy.exc import NoSuchTableError

from sql_safe_mcp.config import AppConfig, PiiConfig
from sql_safe_mcp.db.extras import extras_for
from sql_safe_mcp.db.reflection import list_tables
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.diagnostics import describe_error, log_field, secrets_for
from sql_safe_mcp.pii_audit import SUSPICIOUS_NAME_PARTS, CatalogError
from sql_safe_mcp.security.rules import rule_covers_column, rule_matches_table
from sql_safe_mcp.security.schema import TypeClass, type_class

Kind = Literal["deny", "token", "key", "open"]

# A column whose name contains one of these is denied.
DENY_NAME_PARTS: tuple[str, ...] = ("note", "comment", "memo", "attach", "photo")
# A column whose name contains one of these stays a token. The one place to change that choice.
TOKEN_NAME_PARTS: tuple[str, ...] = SUSPICIOUS_NAME_PARTS
_TOKEN_TYPE_CLASSES: frozenset[TypeClass] = frozenset(
    {"string", "date", "datetime", "time", "uuid", "other"}
)
_NAMES_SHOWN = 5
_PATTERN_CHARACTERS = re.compile(r"([*?\[])")


@dataclass(frozen=True, slots=True)
class ScaffoldColumn:
    name: str
    type_class: TypeClass
    primary_key: bool


# (schema, table, columns); the schema is None on MySQL and MariaDB.
type ScaffoldTable = tuple[str | None, str, tuple[ScaffoldColumn, ...]]


@dataclass(frozen=True, slots=True)
class ScaffoldCatalog:
    databases: Mapping[str, Sequence[ScaffoldTable]]
    visible: int  # databases the login sees, reflected or not


def classify_column(column: ScaffoldColumn) -> Kind:
    """The fixed, conservative rule of the draft: deny, then token, then key, then open."""
    folded = column.name.casefold()
    if column.type_class == "binary" or any(part in folded for part in DENY_NAME_PARTS):
        return "deny"
    if column.type_class in _TOKEN_TYPE_CLASSES or any(part in folded for part in TOKEN_NAME_PARTS):
        return "token"
    if column.primary_key or folded.endswith("id"):
        return "key"
    return "open"


@dataclass(slots=True)
class _ColumnFold:
    name: str
    databases: set[str] = field(default_factory=set)
    kinds: set[Kind] = field(default_factory=set)
    spellings: set[str] = field(default_factory=set)
    protected: bool = False
    ambiguous: bool = False


@dataclass(slots=True)
class _TableFold:
    schema: str | None
    name: str
    databases: set[str] = field(default_factory=set)
    columns: dict[str, _ColumnFold] = field(default_factory=dict)


@dataclass(slots=True)
class _Plan:
    entries: dict[Literal["open", "deny", "key"], list[dict[str, object]]]
    only_in: list[str]
    unlistable: list[str]
    protected: list[str]
    token: int
    reflected: list[str]
    visible: int


def _sorted_names(names: Sequence[str]) -> list[str]:
    return sorted(names, key=lambda name: (name.casefold(), name))


def _qualified(schema: str | None, table: str, column: str | None = None) -> str:
    return ".".join(log_field(part) for part in (schema, table, column) if part)


def _shown(names: Sequence[str]) -> str:
    shown = ", ".join(log_field(name) for name in names[:_NAMES_SHOWN])
    hidden = len(names) - _NAMES_SHOWN
    return f"{shown}, ... (+{hidden} more)" if hidden > 0 else shown


def _fold(catalog: ScaffoldCatalog, pii: PiiConfig) -> dict[tuple[str, str], _TableFold]:
    protecting = [*pii.rules, *pii.deny]
    tables: dict[tuple[str, str], _TableFold] = {}
    for database in _sorted_names(list(catalog.databases)):
        ordered = sorted(
            catalog.databases[database],
            key=lambda item: (
                (item[0] or "").casefold(),
                item[1].casefold(),
                item[0] or "",
                item[1],
            ),
        )
        for schema, name, columns in ordered:
            key = ((schema or "").casefold(), name.casefold())
            folded = tables.setdefault(key, _TableFold(schema=schema, name=name))
            folded.databases.add(database)
            seen: set[str] = set()
            for column in columns:
                cf = column.name.casefold()
                item = folded.columns.setdefault(cf, _ColumnFold(name=column.name))
                if cf in seen:
                    item.ambiguous = True
                seen.add(cf)
                item.databases.add(database)
                item.kinds.add(classify_column(column))
                item.spellings.add(column.name)
                item.protected = item.protected or any(
                    rule_matches_table(rule, database, schema, name)
                    and rule_covers_column(rule, column.name)
                    for rule in protecting
                )
    return tables


def _entry(schema: str | None, table: str, columns: list[str]) -> dict[str, object]:
    # The table is a glob in a rule: escape it so it matches only this table.
    entry: dict[str, object] = {}
    if schema is not None:
        entry["schema"] = schema
    entry["table"] = _PATTERN_CHARACTERS.sub(r"[\1]", table)
    entry["columns"] = columns
    return entry


def _plan(catalog: ScaffoldCatalog, pii: PiiConfig) -> _Plan:
    plan = _Plan(
        entries={"open": [], "deny": [], "key": []},
        only_in=[],
        unlistable=[],
        protected=[],
        token=0,
        reflected=_sorted_names(list(catalog.databases)),
        visible=catalog.visible,
    )
    folded = _fold(catalog, pii)
    for _, table in sorted(folded.items()):
        schema = table.schema
        if schema is not None and "*" in schema:
            plan.unlistable.append(f"{_qualified(schema, table.name)} (the schema name has a '*')")
            plan.token += len(table.columns)
            continue
        listed: dict[Literal["open", "deny", "key"], list[str]] = {
            "open": [],
            "deny": [],
            "key": [],
        }
        unlistable: list[str] = []
        for _, column in sorted(table.columns.items()):
            if column.protected:
                plan.protected.append(_qualified(schema, table.name, column.name))
            elif column.ambiguous or any("*" in spelling for spelling in column.spellings):
                unlistable.extend(_sorted_names(list(column.spellings)))
                plan.token += 1
            elif "deny" in column.kinds:
                listed["deny"].append(column.name)
            elif "token" in column.kinds:
                plan.token += 1
            elif column.databases != table.databases:
                names = _shown(_sorted_names(list(column.databases)))
                plan.only_in.append(
                    f"# only in {names}: {_qualified(schema, table.name, column.name)}"
                )
                plan.token += 1
            elif "key" in column.kinds:
                listed["key"].append(column.name)
            else:
                listed["open"].append(column.name)
        if unlistable:
            names = ", ".join(_qualified(schema, table.name, name) for name in unlistable)
            plan.unlistable.append(names)
        for kind, names_ in listed.items():
            if names_:
                plan.entries[kind].append(_entry(schema, table.name, names_))
    return plan


def _dump(data: object, *, flow: bool = False) -> str:
    return yaml.safe_dump(
        data, default_flow_style=flow, sort_keys=False, width=float("inf")
    ).rstrip("\n")


def _section(key: str, entries: list[dict[str, object]]) -> str:
    return f"{key}: []" if not entries else f"{key}:\n{_dump(entries)}"


def _commented(entry: dict[str, object]) -> list[str]:
    lines = _dump(entry, flow=True).splitlines()
    return [f"#   - {lines[0]}", *(f"#     {line}" for line in lines[1:])]


def render_scaffold(alias: str, catalog: ScaffoldCatalog, pii: PiiConfig) -> str:
    """The draft as text: a YAML fragment for pasting under `pii:` plus review comments."""
    plan = _plan(catalog, pii)
    count = len(plan.reflected)
    scope = f"all {count}" if count == plan.visible else f"{count} of {plan.visible}"
    summary = (
        f"# Summary: open {sum(len(_columns(e)) for e in plan.entries['open'])}, "
        f"deny {sum(len(_columns(e)) for e in plan.entries['deny'])}, "
        f"key {sum(len(_columns(e)) for e in plan.entries['key'])}, token {plan.token}"
    )
    if plan.protected:
        summary += f", protected {len(plan.protected)}"
    lines = [
        f"# Draft pii section for server {log_field(alias)}. "
        "A suggestion, not a decision: review every line.",
        f"# Reflected {scope} databases: {_shown(plan.reflected)}.",
        "# Entries apply to every database of the alias, including ones not reflected.",
        summary,
        "mode: deny-by-default",
        _section("exposed_columns", plan.entries["open"]),
        _section("deny", plan.entries["deny"]),
    ]
    lines.extend(plan.only_in)
    lines.extend(f"# not listable: {item}" for item in plan.unlistable)
    if plan.protected:
        lines.append(f"# protected by an existing rule: {', '.join(plan.protected)}")
    if plan.entries["key"]:
        lines += [
            "# Key columns stay tokens. Open one only if the agent must join or sort by it.",
            "# A key that names a person (patient, member, MRN) is a Safe Harbor identifier (R);",
            "# see docs/health-data.md.",
        ]
        for entry in plan.entries["key"]:
            lines.extend(_commented(entry))
    return "\n".join(lines) + "\n"


def _columns(entry: dict[str, object]) -> list[str]:
    columns = entry["columns"]
    assert isinstance(columns, list)
    return columns


# --- collecting the schema --------------------------------------------------------------------


def _reflect(connection: Connection) -> list[ScaffoldTable]:
    inspector = inspect(connection)
    tables: list[ScaffoldTable] = []
    for table in list_tables(connection):
        try:
            columns = inspector.get_columns(table.name, schema=table.schema_)
            primary = inspector.get_pk_constraint(table.name, schema=table.schema_)
        except NoSuchTableError:
            continue  # listed but gone before reflection (temporary tables)
        keyed = {str(name) for name in primary.get("constrained_columns") or ()}
        tables.append(
            (
                table.schema_,
                table.name,
                tuple(
                    ScaffoldColumn(
                        name=str(item["name"]),
                        type_class=type_class(item["type"]),
                        primary_key=str(item["name"]) in keyed,
                    )
                    for item in columns
                ),
            )
        )
    return tables


def _choose(visible: Sequence[str], requested: Sequence[str]) -> list[str]:
    if not requested:
        return _sorted_names(list(visible))
    chosen: set[str] = set()
    for name in requested:
        match = (
            name
            if name in visible
            else next(
                (
                    item
                    for item in _sorted_names(list(visible))
                    if item.casefold() == name.casefold()
                ),
                None,
            )
        )
        if match is None:
            raise CatalogError(f"database {log_field(name)!r} is not visible to this login")
        chosen.add(match)
    return _sorted_names(list(chosen))


def collect_scaffold_catalog(
    config: AppConfig, alias: str, databases: Sequence[str]
) -> ScaffoldCatalog:
    """Reflect the named databases, or every visible one when none is named."""
    server = config.servers[alias]
    registry = EngineRegistry(config)
    secrets = secrets_for(server.connection_url.get_secret_value(), alias)
    try:
        try:
            with registry.get(alias, None).connect() as connection:
                visible = extras_for(server.engine).list_databases(connection)
        except Exception as exc:
            raise CatalogError(
                f"cannot list databases: {describe_error(exc, secrets, include_message=False)}"
            ) from None
        reflected: dict[str, list[ScaffoldTable]] = {}
        for database in _choose(visible, databases):
            try:
                with registry.get(alias, database).connect() as connection:
                    reflected[database] = _reflect(connection)
            except Exception as exc:
                raise CatalogError(
                    f"cannot reflect database {log_field(database)!r}: "
                    f"{describe_error(exc, secrets, include_message=False)}"
                ) from None
        return ScaffoldCatalog(databases=reflected, visible=len(visible))
    finally:
        registry.dispose()


type ScaffoldCollector = Callable[[AppConfig, str, Sequence[str]], ScaffoldCatalog]


@dataclass(frozen=True, slots=True)
class ScaffoldResult:
    text: str | None  # the draft for stdout; None on failure
    diagnostics: tuple[str, ...]  # lines for stderr
    failed: bool


def scaffold_pii(
    config: AppConfig,
    alias: str,
    databases: Sequence[str],
    collect: ScaffoldCollector = collect_scaffold_catalog,
) -> ScaffoldResult:
    server = config.servers.get(alias)
    if server is None:
        return ScaffoldResult(None, (f"ERROR: unknown server alias {log_field(alias)!r}",), True)
    if server.access_level != "all_pii_safe" or server.pii is None:
        message = (
            f"ERROR: {log_field(alias)}: access_level is {server.access_level}; "
            "only an all_pii_safe alias has a pii section to draft"
        )
        return ScaffoldResult(None, (message,), True)
    try:
        catalog = collect(config, alias, databases)
    except CatalogError as exc:
        return ScaffoldResult(None, (f"ERROR: {log_field(alias)}: {exc}",), True)
    tables = sum(len(entries) for entries in catalog.databases.values())
    if tables == 0:
        message = (
            f"ERROR: {log_field(alias)}: no tables reflected; check the database names "
            "and the login's metadata permissions"
        )
        return ScaffoldResult(None, (message,), True)
    note = f"Reflected {len(catalog.databases)} database(s), {tables} table(s)."
    return ScaffoldResult(render_scaffold(alias, catalog, server.pii), (note,), False)
