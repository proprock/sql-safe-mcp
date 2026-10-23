from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from typing import TypeVar
from uuid import uuid4

from sqlalchemy import Connection, Engine
from sqlalchemy.exc import DBAPIError, OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError

from sql_safe_mcp.config import AppConfig, ServerConfig
from sql_safe_mcp.db.extras import extras_for
from sql_safe_mcp.db.reflection import get_table_definition as reflect_table_definition
from sql_safe_mcp.db.reflection import list_tables as reflect_tables
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.diagnostics import describe_error, secrets_for
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.models import (
    ColumnSource,
    DatabaseList,
    DatabaseSummary,
    ServerList,
    ServerSummary,
    SqlColumn,
    SqlResult,
    StoredProcedureDefinition,
    StoredProcedureList,
    StoredProcedureSummary,
    TableDefinition,
    TableList,
    TableSummary,
)
from sql_safe_mcp.security.dialect import dialect_for
from sql_safe_mcp.security.executor import execute_validated
from sql_safe_mcp.security.pipeline import validate_sql
from sql_safe_mcp.security.schema import ReflectedCatalog, SchemaCache, TableCatalog
from sql_safe_mcp.security.tokens import TokenKeyRegistry

logger = logging.getLogger(__name__)
CatalogFactory = Callable[[Connection, str, str], TableCatalog]
_SCHEMA_CACHE_ENTRIES = 1024
_SCHEMA_CACHE_TTL_SECONDS = 300.0
_TIMEOUT_SQLSTATES = frozenset({"HYT00", "HYT01"})
_CONNECTION_SQLSTATES = frozenset({"08001", "08004"})
_ACCESS_DENIED_SQLSTATES = frozenset({"28000"})
_TIMEOUT_NATIVE_CODES = frozenset({-2})
_CONNECTION_NATIVE_CODES = frozenset({1049, 2003, 4060})
_ACCESS_DENIED_NATIVE_CODES = frozenset({229, 1044, 1045, 18456})
T = TypeVar("T")


def _timeout_error() -> DomainError:
    return DomainError(
        ErrorCode.TIMEOUT,
        "The database operation timed out.",
        retryable=True,
        correlation_id=uuid4().hex,
    )


def _connection_error() -> DomainError:
    return DomainError(
        ErrorCode.CONNECTION_FAILED,
        "Could not connect to the configured database server.",
        retryable=True,
        correlation_id=uuid4().hex,
    )


def _driver_codes(exc: DBAPIError) -> tuple[frozenset[str], frozenset[int]]:
    sqlstates: set[str] = set()
    native_codes: set[int] = set()
    for value in getattr(exc.orig, "args", ()):
        if isinstance(value, str):
            if re.fullmatch(r"[A-Za-z0-9]{5}", value):
                sqlstates.add(value.upper())
            native_codes.update(int(code) for code in re.findall(r"\((-?\d+)\)", value))
        elif isinstance(value, int) and not isinstance(value, bool):
            native_codes.add(value)
    return frozenset(sqlstates), frozenset(native_codes)


def _classify_dbapi_error(exc: DBAPIError) -> DomainError | None:
    sqlstates, native_codes = _driver_codes(exc)
    if sqlstates & _TIMEOUT_SQLSTATES or native_codes & _TIMEOUT_NATIVE_CODES:
        return _timeout_error()
    if sqlstates & _CONNECTION_SQLSTATES or native_codes & _CONNECTION_NATIVE_CODES:
        return _connection_error()
    if sqlstates & _ACCESS_DENIED_SQLSTATES or native_codes & _ACCESS_DENIED_NATIVE_CODES:
        return DomainError(ErrorCode.ACCESS_DENIED, "The database denied this operation.")

    message = str(exc.orig).casefold()
    if any(value in message for value in ("timeout", "timed out", "hyt00", "hyt01")):
        return _timeout_error()
    if any(
        value in message
        for value in (
            "permission denied",
            "permission was denied",
            "access denied",
            "not authorized",
        )
    ):
        return DomainError(ErrorCode.ACCESS_DENIED, "The database denied this operation.")
    if any(
        value in message for value in ("cannot open database", "(4060)", "08001", "08004")
    ) or isinstance(exc, OperationalError):
        return _connection_error()
    return None


def _contains(value: str, needle: str | None) -> bool:
    return needle is None or needle.casefold() in value.casefold()


def _qualified_name(schema: str | None, name: str) -> str:
    return name if schema is None else f"{schema}.{name}"


class DatabaseService:
    def __init__(
        self,
        config: AppConfig,
        registry: EngineRegistry,
        catalog_factory: CatalogFactory | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self._tokens = TokenKeyRegistry.from_config(config)
        self._schema_cache = SchemaCache(_SCHEMA_CACHE_ENTRIES, _SCHEMA_CACHE_TTL_SECONDS)
        self._catalog_factory = catalog_factory or self._reflected_catalog

    def _reflected_catalog(self, connection: Connection, alias: str, database: str) -> TableCatalog:
        return ReflectedCatalog(connection, self._schema_cache, alias, database)

    def _server(self, alias: str) -> ServerConfig:
        try:
            return self.config.servers[alias]
        except KeyError as exc:
            raise DomainError(
                ErrorCode.UNKNOWN_SERVER,
                f"Unknown configured server {alias!r}.",
                "Call list_servers to discover configured aliases.",
            ) from exc

    @staticmethod
    def _require_meta_and_code_access(configured: ServerConfig) -> None:
        if configured.access_level == "metadata":
            raise DomainError(
                ErrorCode.ACCESS_LEVEL_DENIED,
                "Stored procedure tools are available only for meta_and_code or "
                "all_pii_safe servers.",
                "Use a server configured with access_level meta_and_code or all_pii_safe.",
            )

    def _classified(
        self,
        alias: str,
        database: str | None,
        operation: str,
        error: DomainError,
        cause: BaseException,
    ) -> DomainError:
        secrets = secrets_for(self.config.servers[alias].connection_url.get_secret_value(), alias)
        logger.warning(
            "operation failed server=%s database=%s operation=%s code=%s reference=%s error=%s",
            alias,
            database or "-",
            operation,
            error.code,
            error.correlation_id or "-",
            # execute_sql drivers echo caller-influenced values and PII, so no message text.
            describe_error(cause, secrets, include_message=operation != "execute_sql"),
        )
        return error

    def _unexpected(
        self, message: str, alias: str, database: str | None, operation: str, cause: BaseException
    ) -> DomainError:
        error = DomainError.unexpected()
        logger.error(
            "%s; server=%s database=%s operation=%s error_class=%s reference=%s",
            message,
            alias,
            database or "-",
            operation,
            type(cause).__name__,
            error.correlation_id,
        )
        return error

    async def _run(
        self,
        alias: str,
        database: str | None,
        operation_name: str,
        operation: Callable[[Engine], T],
    ) -> T:
        self._server(alias)
        started = time.perf_counter()
        try:
            result = await self.registry.run(alias, database, operation)
        except DomainError:
            raise
        except SQLAlchemyTimeoutError as exc:
            raise self._classified(alias, database, operation_name, _timeout_error(), exc) from exc
        except DBAPIError as exc:
            if error := _classify_dbapi_error(exc):
                raise self._classified(alias, database, operation_name, error, exc) from exc
            raise self._unexpected(
                "Database operation failed", alias, database, operation_name, exc
            ) from exc
        except SQLAlchemyError as exc:
            raise self._unexpected(
                "SQLAlchemy operation failed", alias, database, operation_name, exc
            ) from exc
        except Exception as exc:
            raise self._unexpected(
                "Unexpected database operation failure", alias, database, operation_name, exc
            ) from exc
        logger.info(
            "operation ok server=%s database=%s operation=%s elapsed_ms=%d",
            alias,
            database or "-",
            operation_name,
            (time.perf_counter() - started) * 1000,
        )
        return result

    def list_servers(self) -> ServerList:
        return ServerList(
            servers=[
                ServerSummary(name=alias, engine=server.engine, access_level=server.access_level)
                for alias, server in sorted(
                    self.config.servers.items(), key=lambda item: item[0].casefold()
                )
            ]
        )

    async def list_databases(self, server: str, name_contains: str | None = None) -> DatabaseList:
        configured = self._server(server)

        def operation(engine: Engine) -> list[str]:
            with engine.connect() as connection:
                return extras_for(configured.engine).list_databases(connection)

        names = await self._run(server, None, "list_databases", operation)
        return DatabaseList(
            databases=[
                DatabaseSummary(name=name)
                for name in sorted(names, key=str.casefold)
                if _contains(name, name_contains)
            ]
        )

    async def list_tables(
        self,
        server: str,
        database: str,
        schema: str | None = None,
        name_contains: str | None = None,
    ) -> TableList:
        self._server(server)

        def operation(engine: Engine) -> list[TableSummary]:
            with engine.connect() as connection:
                return reflect_tables(connection)

        tables = await self._run(server, database, "list_tables", operation)
        selected = [
            table
            for table in tables
            if (schema is None or (table.schema_ or "").casefold() == schema.casefold())
            and _contains(table.name, name_contains)
        ]
        selected.sort(key=lambda table: ((table.schema_ or "").casefold(), table.name.casefold()))
        return TableList(tables=selected)

    @staticmethod
    def _resolve_table(tables: list[TableSummary], table: str, schema: str | None) -> TableSummary:
        matches = [
            item
            for item in tables
            if item.name.casefold() == table.casefold()
            and (schema is None or (item.schema_ or "").casefold() == schema.casefold())
        ]
        if not matches:
            raise DomainError(ErrorCode.NOT_FOUND, f"Table {table!r} was not found.")
        if len(matches) > 1:
            candidates = ", ".join(_qualified_name(item.schema_, item.name) for item in matches)
            raise DomainError(
                ErrorCode.AMBIGUOUS_OBJECT,
                f"Table {table!r} is ambiguous.",
                f"Specify schema; candidates: {candidates}.",
            )
        return matches[0]

    async def get_table_definition(
        self, server: str, database: str, table: str, schema: str | None = None
    ) -> TableDefinition:
        self._server(server)

        def operation(engine: Engine) -> TableDefinition:
            with engine.connect() as connection:
                selected = self._resolve_table(reflect_tables(connection), table, schema)
                return reflect_table_definition(connection, selected.schema_, selected.name)

        return await self._run(server, database, "get_table_definition", operation)

    async def list_stored_procedures(
        self,
        server: str,
        database: str,
        schema: str | None = None,
        name_contains: str | None = None,
    ) -> StoredProcedureList:
        configured = self._server(server)
        self._require_meta_and_code_access(configured)

        def operation(engine: Engine) -> list[StoredProcedureSummary]:
            with engine.connect() as connection:
                return extras_for(configured.engine).list_stored_procedures(connection, database)

        procedures = await self._run(server, database, "list_stored_procedures", operation)
        selected = [
            item
            for item in procedures
            if (schema is None or (item.schema_ or "").casefold() == schema.casefold())
            and _contains(item.name, name_contains)
        ]
        selected.sort(key=lambda item: ((item.schema_ or "").casefold(), item.name.casefold()))
        return StoredProcedureList(stored_procedures=selected)

    async def get_stored_procedure(
        self,
        server: str,
        database: str,
        name: str,
        schema: str | None = None,
    ) -> StoredProcedureDefinition:
        configured = self._server(server)
        listing = await self.list_stored_procedures(server, database, schema)
        matches = [
            item for item in listing.stored_procedures if item.name.casefold() == name.casefold()
        ]
        if not matches:
            raise DomainError(ErrorCode.NOT_FOUND, f"Stored procedure {name!r} was not found.")
        if len(matches) > 1:
            candidates = ", ".join(_qualified_name(item.schema_, item.name) for item in matches)
            raise DomainError(
                ErrorCode.AMBIGUOUS_OBJECT,
                f"Stored procedure {name!r} is ambiguous.",
                f"Specify schema; candidates: {candidates}.",
            )
        selected = matches[0]

        def operation(engine: Engine) -> StoredProcedureDefinition | None:
            with engine.connect() as connection:
                return extras_for(configured.engine).get_stored_procedure(
                    connection, database, selected.schema_, selected.name
                )

        result = await self._run(server, database, "get_stored_procedure", operation)
        if result is None:
            raise DomainError(ErrorCode.NOT_FOUND, f"Stored procedure {name!r} was not found.")
        if (
            result.definition is not None
            and len(result.definition) > self.config.runtime.max_definition_chars
        ):
            raise DomainError(
                ErrorCode.DEFINITION_TOO_LARGE,
                "Stored procedure definition exceeds the configured response limit.",
            )
        return result

    async def execute_sql(
        self, server: str, database: str, sql: str, max_rows: int | None = None
    ) -> SqlResult:
        configured = self._server(server)
        if configured.access_level != "all_pii_safe" or configured.pii is None:
            raise DomainError(
                ErrorCode.ACCESS_LEVEL_DENIED,
                "execute_sql is available only for all_pii_safe servers.",
                "Use a server configured with access_level all_pii_safe.",
            )
        runtime = self.config.runtime
        rows_limit = runtime.default_max_rows if max_rows is None else max_rows
        codec = self._tokens.codec_for(server)
        pii = configured.pii
        dialect = dialect_for(configured.engine)

        def operation(engine: Engine) -> SqlResult:
            with engine.connect() as connection:
                validated = validate_sql(
                    sql,
                    alias=server,
                    database=database,
                    catalog=self._catalog_factory(connection, server, database),
                    pii_config=pii,
                    codec=codec,
                    runtime=runtime,
                    max_rows=rows_limit,
                    dialect=dialect,
                )
                executed = execute_validated(connection, validated, codec)
            return SqlResult(
                columns=[
                    SqlColumn(
                        name=column.name,
                        source=None
                        if column.source is None
                        else ColumnSource(
                            schema=column.source.schema or None,
                            table=column.source.table,
                            column=column.source.column,
                        ),
                        protected=column.protected,
                        encoding=column.encoding,
                    )
                    for column in executed.columns
                ],
                rows=[list(row) for row in executed.rows],
                row_count=len(executed.rows),
                truncated=executed.truncated,
            )

        return await self._run(server, database, "execute_sql", operation)
