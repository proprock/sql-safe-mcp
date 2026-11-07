from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import Callable, Sequence
from typing import Any

from mcp import Client
from mcp_types import TextContent
from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError
from typed_columns import typed

from sql_safe_mcp.config import AppConfig, LoggingConfig, ServerConfig
from sql_safe_mcp.mcp_server import create_server
from sql_safe_mcp.security.schema import ColumnSchema


def _config() -> AppConfig:
    return AppConfig(
        version=1,
        servers={
            "legacy": ServerConfig(
                engine="sqlserver",
                connection_url=SecretStr("mssql+pyodbc://u:p@sql/master?driver=x&Encrypt=yes"),
            )
        },
    )


def test_metadata_tool_contracts_and_structured_output() -> None:
    async def scenario() -> None:
        async with Client(create_server(_config()), raise_exceptions=True) as client:
            listing = await client.list_tools()
            assert [tool.name for tool in listing.tools] == [
                "list_servers",
                "list_databases",
                "list_tables",
                "get_table_definition",
                "list_stored_procedures",
                "get_stored_procedure",
                "execute_sql",
            ]
            expected_inputs = {
                "list_servers": (set(), set()),
                "list_databases": ({"server", "name_contains"}, {"server"}),
                "list_tables": (
                    {"server", "database", "schema", "name_contains"},
                    {"server", "database"},
                ),
                "get_table_definition": (
                    {"server", "database", "table", "schema"},
                    {"server", "database", "table"},
                ),
                "list_stored_procedures": (
                    {"server", "database", "schema", "name_contains"},
                    {"server", "database"},
                ),
                "get_stored_procedure": (
                    {"server", "database", "name", "schema"},
                    {"server", "database", "name"},
                ),
                "execute_sql": (
                    {"server", "database", "sql", "max_rows"},
                    {"server", "database", "sql"},
                ),
            }
            for tool in listing.tools:
                properties, required = expected_inputs[tool.name]
                assert set(tool.input_schema.get("properties", {})) == properties
                assert set(tool.input_schema.get("required", [])) == required
                assert tool.annotations is not None
                assert tool.annotations.read_only_hint is True
                assert tool.annotations.open_world_hint is False
            table_list = next(tool for tool in listing.tools if tool.name == "list_tables")
            output_schema = table_list.output_schema
            assert output_schema is not None
            table_item = output_schema["properties"]["tables"]["items"]
            if "$ref" in table_item:
                definition_name = table_item["$ref"].rsplit("/", 1)[-1]
                table_item = output_schema["$defs"][definition_name]
            assert set(table_item["properties"]) == {"schema", "name"}
            assert set(table_item["required"]) == {"schema", "name"}
            result = await client.call_tool("list_servers")
            assert result.is_error is False
            assert result.structured_content == {
                "servers": [{"name": "legacy", "engine": "sqlserver", "access_level": "metadata"}]
            }

    asyncio.run(scenario())


def test_mcp_lifespan_disposes_registry(monkeypatch: Any) -> None:
    instances: list[Any] = []

    class RecordingRegistry:
        def __init__(self, config: AppConfig) -> None:
            self.config = config
            self.disposed = False
            instances.append(self)

        def dispose(self) -> None:
            self.disposed = True

    monkeypatch.setattr("sql_safe_mcp.mcp_server.EngineRegistry", RecordingRegistry)

    async def scenario() -> None:
        async with Client(create_server(_config()), raise_exceptions=True) as client:
            result = await client.call_tool("list_servers")
            assert result.is_error is False
            assert instances[0].disposed is False
        assert instances[0].disposed is True

    asyncio.run(scenario())


def test_domain_error_is_visible_as_tool_error_without_internal_details() -> None:
    async def scenario() -> None:
        async with Client(create_server(_config()), raise_exceptions=True) as client:
            result = await client.call_tool("list_databases", {"server": "missing"})
            assert result.is_error is True
            assert result.structured_content is None
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "[UNKNOWN_SERVER]" in content.text
            assert "password" not in content.text

    asyncio.run(scenario())


KEY = bytes(range(32))


def _secure_config() -> AppConfig:
    return AppConfig.model_validate(
        {
            "version": 1,
            "servers": {
                "legacy": {
                    "engine": "sqlserver",
                    "connection_url": "mssql+pyodbc://u:p@sql/master?driver=x&Encrypt=yes",
                },
                "code": {
                    "engine": "sqlserver",
                    "access_level": "meta_and_code",
                    "connection_url": "mssql+pyodbc://u:p@sql/master?driver=x&Encrypt=yes",
                },
                "secure": {
                    "engine": "sqlserver",
                    "access_level": "all_pii_safe",
                    "connection_url": "mssql+pyodbc://u:p@sql/master?driver=x&Encrypt=yes",
                    "pii_key_env": "K",
                    "pii_key": base64.b64encode(KEY).decode(),
                    "pii": {
                        "rules": [
                            {
                                "database": "*",
                                "schema": "dbo",
                                "table": "Users",
                                "columns": ["Email"],
                            }
                        ]
                    },
                },
                "peds": {
                    "engine": "sqlserver",
                    "access_level": "all_pii_safe",
                    "connection_url": "mssql+pyodbc://u:p@sql/master?driver=x&Encrypt=yes",
                    "pii_key_env": "PK",
                    "pii_key": base64.b64encode(bytes(range(1, 33))).decode(),
                    "pii": {
                        "mode": "deny-by-default",
                        "exposed_columns": [{"table": "Users", "columns": ["Id"]}],
                        "deny": [{"table": "Audit", "columns": ["*"]}],
                    },
                },
            },
        }
    )


class _Result:
    def __init__(self, keys: list[str], rows: list[tuple[Any, ...]]) -> None:
        self._keys, self._rows = keys, rows

    def keys(self) -> list[str]:
        return self._keys

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        return self._rows[:size]

    def close(self) -> None:
        pass


class _Connection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def exec_driver_sql(self, statement: str, parameters: tuple[Any, ...]) -> _Result:
        self.calls.append((statement, parameters))
        return _Result(["Id", "Email"], [(1, "a@b.c")])

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class _Catalog:
    def list_tables(self) -> list[tuple[str, str]]:
        return [("dbo", "Users"), ("dbo", "Audit")]

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        return typed(["Id", "Email"])


def _patch_database(monkeypatch: Any, connection: _Connection) -> None:
    from sql_safe_mcp import mcp_server
    from sql_safe_mcp.service import DatabaseService

    class Engine:
        def connect(self) -> _Connection:
            return connection

    class Registry:
        def __init__(self, config: AppConfig) -> None:
            self.config = config

        async def run(self, alias: str, database: str | None, operation: Callable[..., Any]) -> Any:
            return operation(Engine())

        def dispose(self) -> None:
            pass

    monkeypatch.setattr(mcp_server, "EngineRegistry", Registry)
    monkeypatch.setattr(
        mcp_server,
        "DatabaseService",
        lambda config, registry: DatabaseService(
            config, registry, catalog_factory=lambda *_: _Catalog()
        ),
    )


def test_execute_sql_returns_structured_result_with_tokens(monkeypatch: Any) -> None:
    connection = _Connection()
    _patch_database(monkeypatch, connection)

    async def scenario() -> None:
        async with Client(create_server(_secure_config()), raise_exceptions=True) as client:
            result = await client.call_tool(
                "execute_sql",
                {"server": "secure", "database": "app", "sql": "SELECT Id, Email FROM Users"},
            )
            assert result.is_error is False
            content = result.structured_content
            assert content is not None
            assert content["row_count"] == 1
            assert content["truncated"] is False
            assert [c["name"] for c in content["columns"]] == ["Id", "Email"]
            assert content["columns"][1]["protected"] is True
            assert content["columns"][1]["encoding"] == "token"
            assert content["columns"][1]["source"] == {
                "schema": "dbo",
                "table": "Users",
                "column": "Email",
            }
            assert content["rows"][0][0] == 1
            assert content["rows"][0][1].startswith("pii:v1:")
            assert "a@b.c" not in str(content)

    asyncio.run(scenario())


def test_deny_by_default_alias_tokenizes_every_unlisted_column(monkeypatch: Any) -> None:
    connection = _Connection()
    _patch_database(monkeypatch, connection)

    async def scenario() -> None:
        async with Client(create_server(_secure_config()), raise_exceptions=True) as client:
            result = await client.call_tool(
                "execute_sql",
                {"server": "peds", "database": "app", "sql": "SELECT * FROM Users"},
            )
            assert result.is_error is False
            content = result.structured_content
            assert content is not None
            assert [(c["name"], c["encoding"]) for c in content["columns"]] == [
                ("Id", "json"),
                ("Email", "token"),
            ]
            assert content["rows"][0][1].startswith("pii:v1:")
            assert "a@b.c" not in str(content)

            denied = await client.call_tool(
                "execute_sql",
                {"server": "peds", "database": "app", "sql": "SELECT Id FROM Audit"},
            )
            assert denied.is_error is True
            text = denied.content[0]
            assert isinstance(text, TextContent)
            assert "a denied column cannot be referenced" in text.text

    asyncio.run(scenario())
    assert len(connection.calls) == 1


def test_execute_sql_denied_for_metadata_and_meta_and_code_aliases(monkeypatch: Any) -> None:
    connection = _Connection()
    _patch_database(monkeypatch, connection)

    async def scenario() -> None:
        async with Client(create_server(_secure_config()), raise_exceptions=True) as client:
            for alias in ("legacy", "code"):
                result = await client.call_tool(
                    "execute_sql",
                    {"server": alias, "database": "app", "sql": "SELECT Id FROM Users"},
                )
                assert result.is_error is True
                content = result.content[0]
                assert isinstance(content, TextContent)
                assert "[ACCESS_LEVEL_DENIED]" in content.text

    asyncio.run(scenario())
    assert connection.calls == []


def test_execute_sql_rejected_query_is_a_tool_error_without_execution(monkeypatch: Any) -> None:
    connection = _Connection()
    _patch_database(monkeypatch, connection)

    async def scenario() -> None:
        async with Client(create_server(_secure_config()), raise_exceptions=True) as client:
            result = await client.call_tool(
                "execute_sql",
                {"server": "secure", "database": "app", "sql": "DROP TABLE Users"},
            )
            assert result.is_error is True
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert "[QUERY_REJECTED]" in content.text

    asyncio.run(scenario())
    assert connection.calls == []


def test_execute_sql_driver_error_values_reach_neither_the_tool_error_nor_the_log(
    monkeypatch: Any, caplog: Any
) -> None:
    canary = "canary.person@example.org"

    class Failing(_Connection):
        def exec_driver_sql(self, statement: str, parameters: tuple[Any, ...]) -> _Result:
            raise DBAPIError(statement, parameters, Exception(f"Conversion failed for '{canary}'"))

    _patch_database(monkeypatch, Failing())

    async def scenario() -> None:
        async with Client(create_server(_secure_config()), raise_exceptions=True) as client:
            result = await client.call_tool(
                "execute_sql",
                {"server": "secure", "database": "app", "sql": "SELECT Id FROM Users"},
            )
            assert result.is_error is True
            content = result.content[0]
            assert isinstance(content, TextContent)
            assert canary not in content.text

    with caplog.at_level(logging.DEBUG):
        asyncio.run(scenario())
    assert canary not in caplog.text


def test_execute_sql_audit_line_reaches_the_log_without_changing_the_response(
    monkeypatch: Any, caplog: Any
) -> None:
    _patch_database(monkeypatch, _Connection())
    config = _secure_config().model_copy(
        update={"logging": LoggingConfig(level="ERROR", audit=True)}
    )
    content: dict[str, Any] = {}

    async def scenario() -> None:
        async with Client(create_server(config), raise_exceptions=True) as client:
            result = await client.call_tool(
                "execute_sql",
                {"server": "secure", "database": "app", "sql": "SELECT Id, Email FROM Users"},
            )
            assert result.structured_content is not None
            content.update(result.structured_content)

    with caplog.at_level(logging.INFO, logger="sql_safe_mcp.audit"):
        asyncio.run(scenario())
    (line,) = [r.getMessage() for r in caplog.records if r.name == "sql_safe_mcp.audit"]
    assert line.startswith(
        "audit server=secure database=app tables=dbo.Users "
        "columns=dbo.Users.Email,dbo.Users.Id protected=1 row_count=1 truncated=False "
    )
    assert "a@b.c" not in caplog.text
    assert set(content) == {"columns", "rows", "row_count", "truncated"}
    logging.getLogger("sql_safe_mcp.audit").setLevel(logging.NOTSET)


def test_execute_sql_output_schema_is_typed(monkeypatch: Any) -> None:
    async def scenario() -> None:
        async with Client(create_server(_secure_config()), raise_exceptions=True) as client:
            tool = next(t for t in (await client.list_tools()).tools if t.name == "execute_sql")
            assert tool.annotations is not None
            assert tool.annotations.read_only_hint is True
            assert tool.output_schema is not None
            assert set(tool.output_schema["properties"]) == {
                "columns",
                "rows",
                "row_count",
                "truncated",
            }

    asyncio.run(scenario())


def test_execute_sql_output_schema_lists_the_suppressed_encoding() -> None:
    async def scenario() -> None:
        async with Client(create_server(_secure_config()), raise_exceptions=True) as client:
            tool = next(t for t in (await client.list_tools()).tools if t.name == "execute_sql")
            assert tool.output_schema is not None
            encoding = tool.output_schema["$defs"]["SqlColumn"]["properties"]["encoding"]
            assert "suppressed" in encoding["enum"]

    asyncio.run(scenario())


def test_create_server_applies_the_configured_log_level() -> None:
    config = _config().model_copy(update={"logging": LoggingConfig(level="DEBUG")})
    logging.getLogger("sql_safe_mcp").setLevel(logging.NOTSET)

    server = create_server(config)

    assert logging.getLogger("sql_safe_mcp").level == logging.DEBUG
    assert logging.getLogger("sqlalchemy").level == logging.WARNING
    assert server.settings.log_level == "DEBUG"
