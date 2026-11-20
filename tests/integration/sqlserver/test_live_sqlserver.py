from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest
from live_support import LiveDatabase, quote_identifier
from mcp import Client
from mcp_types import TextContent
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.db.reflection import get_table_definition as reflect_table_definition
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.mcp_server import create_server

pytestmark = pytest.mark.integration


def test_live_all_metadata_tools(live_database: LiveDatabase) -> None:
    reflection_engine = create_engine(
        make_url(live_database.config.servers["legacy"].connection_url.get_secret_value()).set(
            database=live_database.database
        )
    )
    try:
        with reflection_engine.connect() as connection:
            reflected = reflect_table_definition(connection, live_database.alpha_schema, "Users")
        assert [column.name for column in reflected.columns] == [
            "TenantId",
            "Id",
            "ParentId",
            "Email",
            "Amount",
            "DisplayKey",
        ]
    finally:
        reflection_engine.dispose()

    async def scenario() -> None:
        async with Client(create_server(live_database.config), raise_exceptions=True) as client:
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
            servers = await client.call_tool("list_servers")
            assert servers.is_error is False
            assert {item["name"] for item in servers.structured_content["servers"]} == {
                "legacy",
                "hidden",
                "denied",
                "secure",
                "secure2",
                "exact",
                "exact_deny",
            }
            databases = await client.call_tool(
                "list_databases",
                {"server": "legacy", "name_contains": live_database.database.upper()},
            )
            assert databases.structured_content == {"databases": [{"name": live_database.database}]}
            tables = await client.call_tool(
                "list_tables",
                {
                    "server": "legacy",
                    "database": live_database.database,
                    "name_contains": "users",
                },
            )
            assert {
                (item["schema"], item["name"]) for item in tables.structured_content["tables"]
            } == {
                (live_database.alpha_schema, "Users"),
                (live_database.beta_schema, "Users"),
            }
            definition = await client.call_tool(
                "get_table_definition",
                {
                    "server": "legacy",
                    "database": live_database.database,
                    "schema": live_database.alpha_schema,
                    "table": "users",
                },
            )
            payload = definition.structured_content
            assert [column["name"] for column in payload["columns"]] == [
                "TenantId",
                "Id",
                "ParentId",
                "Email",
                "Amount",
                "DisplayKey",
            ]
            assert payload["primary_key"]["columns"] == ["TenantId", "Id"]
            assert payload["foreign_keys"][0]["columns"] == ["TenantId", "ParentId"]
            assert payload["unique_constraints"][0]["columns"] == ["TenantId", "Email"]
            assert any(index["name"] == "IX_Users_Email" for index in payload["indexes"])
            procedures = await client.call_tool(
                "list_stored_procedures",
                {
                    "server": "legacy",
                    "database": live_database.database,
                    "schema": live_database.alpha_schema,
                    "name_contains": "proc",
                },
            )
            assert {
                item["name"] for item in procedures.structured_content["stored_procedures"]
            } == {
                "VisibleProc",
                "HiddenProc",
            }
            procedure = await client.call_tool(
                "get_stored_procedure",
                {
                    "server": "legacy",
                    "database": live_database.database,
                    "schema": live_database.alpha_schema,
                    "name": "visibleproc",
                },
            )
            assert procedure.structured_content["definition_available"] is True
            assert "CREATE PROCEDURE" in procedure.structured_content["definition"].upper()

    asyncio.run(scenario())


def test_live_safe_error_and_permission_paths(live_database: LiveDatabase) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_database.config), raise_exceptions=True) as client:
            ambiguous = await client.call_tool(
                "get_table_definition",
                {"server": "legacy", "database": live_database.database, "table": "USERS"},
            )
            assert ambiguous.is_error is True
            ambiguous_content = ambiguous.content[0]
            assert isinstance(ambiguous_content, TextContent)
            assert "AMBIGUOUS_OBJECT" in ambiguous_content.text
            missing = await client.call_tool(
                "get_table_definition",
                {
                    "server": "legacy",
                    "database": live_database.database,
                    "table": "MissingTable",
                },
            )
            assert missing.is_error is True
            missing_content = missing.content[0]
            assert isinstance(missing_content, TextContent)
            assert "NOT_FOUND" in missing_content.text
            hidden = await client.call_tool(
                "get_stored_procedure",
                {
                    "server": "hidden",
                    "database": live_database.database,
                    "schema": live_database.alpha_schema,
                    "name": "HiddenProc",
                },
            )
            assert hidden.is_error is False
            assert hidden.structured_content["definition"] is None
            assert hidden.structured_content["definition_available"] is False
            denied = await client.call_tool("list_databases", {"server": "denied"})
            assert denied.is_error is True
            denied_content = denied.content[0]
            assert isinstance(denied_content, TextContent)
            assert "ACCESS_DENIED" in denied_content.text
            invalid_database = await client.call_tool(
                "list_tables",
                {"server": "legacy", "database": f"missing_{uuid4().hex}"},
            )
            assert invalid_database.is_error is True
            invalid_content = invalid_database.content[0]
            assert isinstance(invalid_content, TextContent)
            assert "CONNECTION_FAILED" in invalid_content.text

    asyncio.run(scenario())


def test_live_partially_scoped_login(live_database: LiveDatabase) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_database.config), raise_exceptions=True) as client:
            visible = await client.call_tool(
                "list_databases",
                {"server": "hidden", "name_contains": live_database.database},
            )
            assert visible.structured_content == {"databases": [{"name": live_database.database}]}
            outside = await client.call_tool(
                "list_databases",
                {"server": "hidden", "name_contains": live_database.restricted_database},
            )
            assert outside.structured_content == {"databases": []}

            tables = await client.call_tool(
                "list_tables", {"server": "hidden", "database": live_database.database}
            )
            names = {(item["schema"], item["name"]) for item in tables.structured_content["tables"]}
            assert names == {(live_database.alpha_schema, "ScopedVisible")}

            for table, expected_error in (
                ("ScopedVisible", False),
                ("Canary", True),
                ("MissingTable", True),
            ):
                result = await client.call_tool(
                    "get_table_definition",
                    {
                        "server": "hidden",
                        "database": live_database.database,
                        "schema": live_database.alpha_schema,
                        "table": table,
                    },
                )
                assert result.is_error is expected_error
                if expected_error:
                    content = result.content[0]
                    assert isinstance(content, TextContent)
                    assert "[NOT_FOUND]" in content.text
                else:
                    assert result.structured_content["name"] == "ScopedVisible"

            procedures = await client.call_tool(
                "list_stored_procedures",
                {"server": "hidden", "database": live_database.database},
            )
            procedure_names = {
                item["name"] for item in procedures.structured_content["stored_procedures"]
            }
            assert "HiddenProc" in procedure_names
            assert "VisibleProc" not in procedure_names
            inaccessible_procedure = await client.call_tool(
                "get_stored_procedure",
                {
                    "server": "hidden",
                    "database": live_database.database,
                    "schema": live_database.alpha_schema,
                    "name": "VisibleProc",
                },
            )
            content = inaccessible_procedure.content[0]
            assert isinstance(content, TextContent)
            assert "[NOT_FOUND]" in content.text

            for tool, extra in (
                ("list_tables", {}),
                ("get_table_definition", {"table": "ScopedVisible"}),
                ("list_stored_procedures", {}),
            ):
                result = await client.call_tool(
                    tool,
                    {"server": "hidden", "database": live_database.restricted_database, **extra},
                )
                content = result.content[0]
                assert isinstance(content, TextContent)
                assert result.is_error is True
                assert "[CONNECTION_FAILED]" in content.text
                assert live_database.restricted_database not in content.text

    asyncio.run(scenario())


def test_live_concurrent_calls_do_not_share_connections(live_database: LiveDatabase) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_database.config), raise_exceptions=True) as client:
            results = await asyncio.gather(
                *(
                    client.call_tool(
                        "list_tables",
                        {"server": "legacy", "database": live_database.database},
                    )
                    for _ in range(8)
                )
            )
            assert all(result.is_error is False for result in results)

    asyncio.run(scenario())


def test_live_statement_timeout_and_pool_disposal(
    live_database: LiveDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    instances: list[EngineRegistry] = []

    class CapturingRegistry(EngineRegistry):
        def __init__(self, config: AppConfig) -> None:
            super().__init__(config)
            instances.append(self)

    monkeypatch.setattr("sql_safe_mcp.mcp_server.EngineRegistry", CapturingRegistry)
    lock_engine = create_engine(live_database.admin_url.set(database=live_database.database))
    try:
        with lock_engine.connect() as lock_connection:
            transaction = lock_connection.begin()
            try:
                lock_connection.execute(
                    text(
                        f"ALTER TABLE {quote_identifier(live_database.alpha_schema)}.[Users] "
                        "ADD [TimeoutProbe] int NULL"
                    )
                )

                async def scenario() -> Any:
                    async with Client(
                        create_server(live_database.config), raise_exceptions=True
                    ) as client:
                        return await client.call_tool(
                            "get_table_definition",
                            {
                                "server": "legacy",
                                "database": live_database.database,
                                "schema": live_database.alpha_schema,
                                "table": "Users",
                            },
                        )

                result = asyncio.run(scenario())
                assert result.is_error is True
                content = result.content[0]
                assert isinstance(content, TextContent)
                assert "TIMEOUT" in content.text
            finally:
                transaction.rollback()
    finally:
        lock_engine.dispose()

    assert len(instances) == 1
    assert instances[0].cached_engine_count == 0
