from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass
from threading import Lock
from typing import Literal, Protocol

from sqlalchemy import Connection, inspect
from sqlalchemy import types as sqltypes
from sqlalchemy.exc import NoSuchTableError
from sqlglot import exp

from sql_safe_mcp.db.reflection import list_tables as reflect_tables
from sql_safe_mcp.security.dialect import SQLSERVER, SqlDialect
from sql_safe_mcp.security.parser import reject
from sql_safe_mcp.security.reasons import Reason

TypeClass = Literal[
    "string",
    "integer",
    "float",
    "decimal",
    "bool",
    "date",
    "time",
    "datetime",
    "uuid",
    "binary",
    "other",
]

# Order matters: Float and Boolean are checked before their broader parents.
_TYPE_CLASSES: tuple[tuple[tuple[type, ...], TypeClass], ...] = (
    ((sqltypes.Boolean,), "bool"),
    ((sqltypes.Integer,), "integer"),
    ((sqltypes.Float,), "float"),
    ((sqltypes.Numeric,), "decimal"),
    ((sqltypes.String,), "string"),
    ((sqltypes.DateTime,), "datetime"),
    ((sqltypes.Date,), "date"),
    ((sqltypes.Time,), "time"),
    ((sqltypes.Uuid,), "uuid"),
    ((sqltypes._Binary,), "binary"),
)


def type_class(column_type: object) -> TypeClass:
    """Map a reflected SQLAlchemy type to the coarse class a PII token is checked against."""
    for bases, name in _TYPE_CLASSES:
        if isinstance(column_type, bases):
            return name
    return "other"


@dataclass(frozen=True, slots=True)
class ColumnSchema:
    name: str
    type_class: TypeClass


@dataclass(frozen=True, slots=True)
class TableSchema:
    schema: str
    name: str
    columns: tuple[ColumnSchema, ...]


class TableCatalog(Protocol):
    """Reflected user base tables of one alias and database."""

    def list_tables(self) -> Sequence[tuple[str, str]]: ...

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]: ...


class SchemaCache:
    """Small thread-safe LRU with a time-to-live for immutable reflection results."""

    def __init__(
        self,
        max_entries: int,
        ttl_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_entries = max_entries
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._entries: OrderedDict[Hashable, tuple[float, tuple]] = OrderedDict()
        self._lock = Lock()

    def get(self, key: Hashable) -> tuple | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, value = entry
            if self._clock() - stored_at >= self._ttl_seconds:
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return value

    def put(self, key: Hashable, value: tuple) -> None:
        with self._lock:
            self._entries[key] = (self._clock(), value)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)


class ReflectedCatalog:
    """Inspector-backed catalog; cache keys always include server alias and database."""

    def __init__(
        self, connection: Connection, cache: SchemaCache, alias: str, database: str
    ) -> None:
        self._connection = connection
        self._cache = cache
        self._scope = (alias, database)

    def list_tables(self) -> list[tuple[str, str]]:
        key = (*self._scope, "tables")
        cached = self._cache.get(key)
        if cached is None:
            cached = tuple(
                (table.schema_ or "", table.name) for table in reflect_tables(self._connection)
            )
            self._cache.put(key, cached)
        return list(cached)

    def columns(self, schema: str, table: str) -> tuple[ColumnSchema, ...]:
        key = (*self._scope, "columns", schema, table)
        cached = self._cache.get(key)
        if cached is None:
            try:
                reflected = inspect(self._connection).get_columns(table, schema=schema or None)
            except NoSuchTableError as exc:
                raise reject(Reason.TABLE_GONE) from exc
            cached = tuple(
                ColumnSchema(str(column["name"]), type_class(column.get("type")))
                for column in reflected
            )
            self._cache.put(key, cached)
        return cached


def _match(tables: Sequence[tuple[str, str]], schema: str | None, name: str) -> tuple[str, str]:
    folded_name = name.casefold()
    folded_schema = None if schema is None else schema.casefold()
    matches = [
        (table_schema, table_name)
        for table_schema, table_name in tables
        if table_name.casefold() == folded_name
        and (folded_schema is None or table_schema.casefold() == folded_schema)
    ]
    if len(matches) != 1:
        raise reject(Reason.TABLE_NOT_FOUND)
    return matches[0]


def resolve_tables(
    query: exp.Select, catalog: TableCatalog, dialect: SqlDialect = SQLSERVER
) -> tuple[TableSchema, ...]:
    """Resolve every raw-AST table against reflection and rewrite it to its reflected name.

    Raises QUERY_REJECTED for missing, ambiguous, system, and cross-database objects.
    """
    available = list(catalog.list_tables())
    resolved: list[TableSchema] = []
    for table in query.find_all(exp.Table):
        if table.args.get("catalog") or not isinstance(table.this, exp.Identifier):
            raise reject(Reason.TABLE_SCOPE)
        if not dialect.has_schema and table.db:
            raise reject(Reason.TABLE_SCOPE)  # db.table is a cross-database reference
        schema = table.db or None
        schema_name, table_name = _match(available, schema, table.name)
        resolved.append(
            TableSchema(schema_name, table_name, tuple(catalog.columns(schema_name, table_name)))
        )
        table.set("this", exp.to_identifier(table_name, quoted=True))
        if dialect.has_schema:
            table.set("db", exp.to_identifier(schema_name, quoted=True))
    return tuple(resolved)
