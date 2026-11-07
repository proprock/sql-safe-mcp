from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from sql_safe_mcp import __version__
from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.diagnostics import configure_logging
from sql_safe_mcp.errors import DomainError
from sql_safe_mcp.models import (
    DatabaseList,
    ServerList,
    SqlResult,
    StoredProcedureDefinition,
    StoredProcedureList,
    TableDefinition,
    TableList,
)
from sql_safe_mcp.service import DatabaseService

logger = logging.getLogger(__name__)
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)


@dataclass(slots=True)
class AppContext:
    service: DatabaseService


async def _domain_call[T](operation: Callable[[], Awaitable[T]]) -> T:
    try:
        return await operation()
    except DomainError as exc:
        raise ToolError(str(exc)) from exc


def create_server(config: AppConfig) -> MCPServer[AppContext]:
    @asynccontextmanager
    async def lifespan(_server: MCPServer[AppContext]) -> AsyncIterator[AppContext]:
        registry = EngineRegistry(config)
        try:
            yield AppContext(service=DatabaseService(config, registry))
        finally:
            registry.dispose()

    configure_logging(config.logging.level, config.logging.audit)
    for alias, configured in config.servers.items():
        if configured.access_level == "all_pii_safe" and not configured.require_tls:
            logger.warning(
                "server=%s require_tls=false: PII may travel without verified TLS", alias
            )
    server: MCPServer[AppContext] = MCPServer(
        "sql-safe-mcp",
        description="Minimal, read-only, PII-safe SQL database navigation.",
        version=__version__,
        lifespan=lifespan,
        log_level=config.logging.level,
    )

    @server.tool(annotations=READ_ONLY)
    async def list_servers(ctx: Context[AppContext]) -> ServerList:
        """List explicitly configured database server aliases."""
        return ctx.request_context.lifespan_context.service.list_servers()

    @server.tool(annotations=READ_ONLY)
    async def list_databases(
        server: str,
        ctx: Context[AppContext],
        name_contains: str | None = None,
    ) -> DatabaseList:
        """List databases visible to the configured credentials."""
        service = ctx.request_context.lifespan_context.service
        return await _domain_call(lambda: service.list_databases(server, name_contains))

    @server.tool(annotations=READ_ONLY)
    async def list_tables(
        server: str,
        database: str,
        ctx: Context[AppContext],
        schema: str | None = None,
        name_contains: str | None = None,
    ) -> TableList:
        """List base tables, optionally filtering by schema and a name substring."""
        service = ctx.request_context.lifespan_context.service
        return await _domain_call(
            lambda: service.list_tables(server, database, schema, name_contains)
        )

    @server.tool(annotations=READ_ONLY)
    async def get_table_definition(
        server: str,
        database: str,
        table: str,
        ctx: Context[AppContext],
        schema: str | None = None,
    ) -> TableDefinition:
        """Get columns, keys, constraints, and indexes for one table."""
        service = ctx.request_context.lifespan_context.service
        return await _domain_call(
            lambda: service.get_table_definition(server, database, table, schema)
        )

    @server.tool(annotations=READ_ONLY)
    async def list_stored_procedures(
        server: str,
        database: str,
        ctx: Context[AppContext],
        schema: str | None = None,
        name_contains: str | None = None,
    ) -> StoredProcedureList:
        """List stored procedures without expanding their definitions."""
        service = ctx.request_context.lifespan_context.service
        return await _domain_call(
            lambda: service.list_stored_procedures(server, database, schema, name_contains)
        )

    @server.tool(annotations=READ_ONLY)
    async def get_stored_procedure(
        server: str,
        database: str,
        name: str,
        ctx: Context[AppContext],
        schema: str | None = None,
    ) -> StoredProcedureDefinition:
        """Get the original definition of one stored procedure when visible."""
        service = ctx.request_context.lifespan_context.service
        return await _domain_call(
            lambda: service.get_stored_procedure(server, database, name, schema)
        )

    @server.tool(annotations=READ_ONLY)
    async def execute_sql(
        server: str,
        database: str,
        sql: str,
        ctx: Context[AppContext],
        max_rows: int | None = None,
    ) -> SqlResult:
        """Run one restricted SELECT on an all_pii_safe server; protected columns return tokens."""
        service = ctx.request_context.lifespan_context.service
        return await _domain_call(lambda: service.execute_sql(server, database, sql, max_rows))

    return server
