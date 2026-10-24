"""One MCP server over SQL Server, MySQL, and MariaDB at once (the release matrix).

Needs all three test servers, so it is run by scripts/test-matrix.ps1 and never by the
single-engine gates.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from live_support import LiveDatabase, live_database
from mcp import Client
from mcp_types import TextContent
from mysql_support import LiveMySql, live_mariadb_only, live_mysql_only

from sql_safe_mcp.config import AppConfig, RuntimeConfig, load_config
from sql_safe_mcp.mcp_server import create_server
from sql_safe_mcp.security.tokens import TokenCodec

pytestmark = pytest.mark.integration

__all__ = ["live_database", "live_mariadb_only", "live_mysql_only"]


@dataclass(frozen=True)
class EngineCase:
    engine: str
    meta: str  # metadata alias
    secure: str  # all_pii_safe alias
    key: bytes
    database: str  # metadata database
    sql_database: str
    table: str  # metadata table name
    schema: str | None
    issue_query: str  # deterministic projection that returns two PII tokens
    query: str  # execute_sql text with {token}
    in_query: str  # execute_sql text with {first} and {second}
    email: str


def _cases(mssql: LiveDatabase, mysql: LiveMySql, maria: LiveMySql) -> list[EngineCase]:
    cases = [
        EngineCase(
            "sqlserver",
            "mssql_meta",
            "mssql",
            mssql.pii_key,
            mssql.database,
            mssql.database,
            "Users",
            mssql.alpha_schema,
            f"SELECT Email AS Contact FROM [{mssql.alpha_schema}].[Users] "
            "WHERE TenantId = 1 AND Id IN (1, 2) ORDER BY Id",
            f"SELECT Id FROM [{mssql.alpha_schema}].[Users] WHERE Email = '{{token}}'",
            f"SELECT Id FROM [{mssql.alpha_schema}].[Users] "
            "WHERE Email IN ('{first}', '{second}') ORDER BY Id",
            mssql.emails[0],
        )
    ]
    for prefix, live in (("mysql", mysql), ("maria", maria)):
        cases.append(
            EngineCase(
                live.engine,
                f"{prefix}_meta",
                prefix,
                live.key,
                live.database,
                live.sql_database,
                "users",
                None,
                "SELECT email AS contact FROM people WHERE id IN (1, 2) ORDER BY id",
                "SELECT id FROM people WHERE email = '{token}'",
                "SELECT id FROM people WHERE email IN ('{first}', '{second}') ORDER BY id",
                "a@example.com",
            )
        )
    return cases


def _combined(mssql: LiveDatabase, mysql: LiveMySql, maria: LiveMySql) -> AppConfig:
    servers = {
        "mssql_meta": mssql.config.servers["legacy"],
        "mssql": mssql.config.servers["secure"],
        "mysql_meta": mysql.config.servers["app"],
        "mysql": mysql.sql_config.servers["secure"],
        "maria_meta": maria.config.servers["app"],
        "maria": maria.sql_config.servers["secure"],
    }
    return AppConfig(
        version=1, runtime=RuntimeConfig(statement_timeout_seconds=10), servers=servers
    )


def _text(result: Any) -> str:
    content = result.content[0]
    assert isinstance(content, TextContent)
    return content.text


# Engine-specific free-form details: their presence differs per engine, their keys are not contract.
_OPAQUE = {"options", "identity", "computed"}


def _keys(value: Any) -> Any:
    """The contract shape of a response: field names and list element shapes, never values."""
    if isinstance(value, dict):
        return {key: "opaque" if key in _OPAQUE else _keys(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted({repr(_keys(item)) for item in value})
    return "value"


def test_same_public_contract_and_token_isolation_on_three_engines(
    live_database: LiveDatabase,
    live_mysql_only: LiveMySql,
    live_mariadb_only: LiveMySql,
) -> None:
    cases = _cases(live_database, live_mysql_only, live_mariadb_only)
    config = _combined(live_database, live_mysql_only, live_mariadb_only)

    async def scenario() -> None:
        async with Client(create_server(config), raise_exceptions=True) as client:
            servers = await client.call_tool("list_servers")
            engines = {
                item["name"]: item["engine"] for item in servers.structured_content["servers"]
            }
            assert {case.secure: case.engine for case in cases} | {
                case.meta: case.engine for case in cases
            } == engines

            shapes: dict[str, list[Any]] = {
                "list_databases": [],
                "list_tables": [],
                "get_table_definition": [],
                "list_stored_procedures": [],
                "execute_sql": [],
            }
            for case in cases:
                databases = await client.call_tool("list_databases", {"server": case.meta})
                shapes["list_databases"].append(_keys(databases.structured_content))
                assert any(
                    item["name"] == case.database
                    for item in databases.structured_content["databases"]
                )

                tables = await client.call_tool(
                    "list_tables", {"server": case.meta, "database": case.database}
                )
                shapes["list_tables"].append(_keys(tables.structured_content))
                assert case.table.casefold() in {
                    item["name"].casefold() for item in tables.structured_content["tables"]
                }

                arguments: dict[str, Any] = {
                    "server": case.meta,
                    "database": case.database,
                    "table": case.table,
                }
                if case.schema is not None:
                    arguments["schema"] = case.schema
                definition = await client.call_tool("get_table_definition", arguments)
                shapes["get_table_definition"].append(_keys(definition.structured_content))
                payload = definition.structured_content
                assert (payload["schema"] is None) == (case.schema is None)
                assert payload["primary_key"]["columns"]

                procedures = await client.call_tool(
                    "list_stored_procedures", {"server": case.meta, "database": case.database}
                )
                shapes["list_stored_procedures"].append(_keys(procedures.structured_content))

                own = TokenCodec(case.secure, case.key).encrypt(case.email)
                result = await client.call_tool(
                    "execute_sql",
                    {
                        "server": case.secure,
                        "database": case.sql_database,
                        "sql": case.query.format(token=own),
                    },
                )
                assert result.is_error is False, _text(result)
                assert result.structured_content["rows"], case.engine
                shapes["execute_sql"].append(_keys(result.structured_content))

            for tool, tool_shapes in shapes.items():
                assert all(shape == tool_shapes[0] for shape in tool_shapes), tool

            failures = set()
            for target in cases:
                for source in cases:
                    if source is target:
                        continue
                    tokens = (
                        TokenCodec(source.secure, source.key).encrypt(source.email),
                        TokenCodec(source.secure, target.key).encrypt(source.email),
                        "pii:v1:AAAA",
                    )
                    for token in tokens:
                        bad = await client.call_tool(
                            "execute_sql",
                            {
                                "server": target.secure,
                                "database": target.sql_database,
                                "sql": target.query.format(token=token),
                            },
                        )
                        assert bad.is_error is True
                        assert "INVALID_PII_TOKEN" in _text(bad)
                        failures.add(_text(bad))
            assert len(failures) == 1, failures

    asyncio.run(scenario())


def test_returned_tokens_round_trip_and_are_alias_bound_on_three_engines(
    live_database: LiveDatabase,
    live_mysql_only: LiveMySql,
    live_mariadb_only: LiveMySql,
) -> None:
    cases = _cases(live_database, live_mysql_only, live_mariadb_only)
    config = _combined(live_database, live_mysql_only, live_mariadb_only)

    async def scenario() -> None:
        async with Client(create_server(config), raise_exceptions=True) as client:
            issued: dict[str, str] = {}
            for case in cases:
                first = await client.call_tool(
                    "execute_sql",
                    {
                        "server": case.secure,
                        "database": case.sql_database,
                        "sql": case.issue_query,
                    },
                )
                assert first.is_error is False, _text(first)
                payload = first.structured_content
                assert payload["columns"][0]["name"].casefold() == "contact"
                assert payload["columns"][0]["source"]["column"].casefold() == "email"
                tokens = [row[0] for row in payload["rows"]]
                assert len(tokens) == 2
                assert all(
                    isinstance(token, str) and token.startswith("pii:v1:") for token in tokens
                )

                equality = await client.call_tool(
                    "execute_sql",
                    {
                        "server": case.secure,
                        "database": case.sql_database,
                        "sql": case.query.format(token=tokens[0]),
                    },
                )
                assert equality.is_error is False, _text(equality)
                assert equality.structured_content["rows"] == [[1]]

                membership = await client.call_tool(
                    "execute_sql",
                    {
                        "server": case.secure,
                        "database": case.sql_database,
                        "sql": case.in_query.format(first=tokens[0], second=tokens[1]),
                    },
                )
                assert membership.is_error is False, _text(membership)
                assert membership.structured_content["rows"] == [[1], [2]]
                issued[case.secure] = tokens[0]

            for target in cases:
                for source in cases:
                    if source is target:
                        continue
                    result = await client.call_tool(
                        "execute_sql",
                        {
                            "server": target.secure,
                            "database": target.sql_database,
                            "sql": target.query.format(token=issued[source.secure]),
                        },
                    )
                    assert result.is_error is True
                    assert "INVALID_PII_TOKEN" in _text(result)

    asyncio.run(scenario())


def test_live_shared_pii_rules_apply_only_after_config_resolution(
    live_database: LiveDatabase,
    live_mysql_only: LiveMySql,
    live_mariadb_only: LiveMySql,
    tmp_path: Path,
) -> None:
    """A real MCP client observes flattened glob rules on every supported engine."""

    def url(config: AppConfig, alias: str) -> str:
        return config.servers[alias].connection_url.get_secret_value()

    path = tmp_path / "shared-pii.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "pii_rules": [
                    {"rules": [{"database": "*", "table": "User?", "columns": ["Email"]}]},
                    {
                        "name": "mysql_people",
                        "rules": [{"database": "*", "table": "peopl?", "columns": ["email"]}],
                    },
                    {
                        "name": "not_included",
                        "rules": [{"database": "*", "table": "Audit*", "columns": ["IpAddress"]}],
                    },
                ],
                "servers": {
                    "mssql_meta": {
                        "engine": "sqlserver",
                        "connection_url": url(live_database.config, "legacy"),
                    },
                    "mssql": {
                        "engine": "sqlserver",
                        "access_level": "all_pii_safe",
                        "connection_url": url(live_database.config, "secure"),
                        "pii_key_env": "MATRIX_MSSQL_KEY",
                    },
                    **{
                        alias: {
                            "engine": live.engine,
                            "access_level": "all_pii_safe",
                            "connection_url": url(live.sql_config, "secure"),
                            "pii_key_env": key_name,
                            "pii": {
                                "include": ["mysql_people"],
                                "rules": [
                                    {
                                        "database": "*",
                                        "table": "Nothing?",
                                        "columns": ["value"],
                                    }
                                ],
                            },
                        }
                        for alias, live, key_name in (
                            ("mysql", live_mysql_only, "MATRIX_MYSQL_KEY"),
                            ("maria", live_mariadb_only, "MATRIX_MARIA_KEY"),
                        )
                    },
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config = load_config(
        path,
        {
            "MATRIX_MSSQL_KEY": base64.b64encode(live_database.pii_key).decode(),
            "MATRIX_MYSQL_KEY": base64.b64encode(live_mysql_only.key).decode(),
            "MATRIX_MARIA_KEY": base64.b64encode(live_mariadb_only.key).decode(),
        },
    )
    mssql_pii = config.servers["mssql"].pii
    mysql_pii = config.servers["mysql"].pii
    assert mssql_pii is not None
    assert mysql_pii is not None
    assert [rule.table for rule in mssql_pii.rules] == ["User?"]
    assert [rule.table for rule in mysql_pii.rules] == [
        "User?",
        "peopl?",
        "Nothing?",
    ]

    async def scenario() -> None:
        async with Client(create_server(config), raise_exceptions=True) as client:
            mssql_token = TokenCodec("mssql", live_database.pii_key).encrypt(
                live_database.emails[0]
            )
            mssql = await client.call_tool(
                "execute_sql",
                {
                    "server": "mssql",
                    "database": live_database.database,
                    "sql": (
                        f"SELECT Id FROM [{live_database.alpha_schema}].[Users] "
                        f"WHERE Email = '{mssql_token}'"
                    ),
                },
            )
            assert mssql.is_error is False, _text(mssql)
            for alias, live in (("mysql", live_mysql_only), ("maria", live_mariadb_only)):
                token = TokenCodec(alias, live.key).encrypt("a@example.com")
                result = await client.call_tool(
                    "execute_sql",
                    {
                        "server": alias,
                        "database": live.sql_database,
                        "sql": f"SELECT id FROM people WHERE email = '{token}'",
                    },
                )
                assert result.is_error is False, _text(result)

            denied = await client.call_tool(
                "execute_sql",
                {
                    "server": "mssql_meta",
                    "database": live_database.database,
                    "sql": "SELECT Id FROM Users",
                },
            )
            assert denied.is_error is True
            assert "ACCESS_LEVEL_DENIED" in _text(denied)

    asyncio.run(scenario())


def test_live_deny_by_default_and_deny_list_on_three_engines(
    live_database: LiveDatabase,
    live_mysql_only: LiveMySql,
    live_mariadb_only: LiveMySql,
    tmp_path: Path,
) -> None:
    """Unlisted columns come back as tokens and denied columns are rejected on every engine."""

    def url(config: AppConfig, alias: str) -> str:
        return config.servers[alias].connection_url.get_secret_value()

    engines = (
        ("mssql", "sqlserver", live_database.config, "secure", "MATRIX_MSSQL_KEY"),
        ("mysql", live_mysql_only.engine, live_mysql_only.sql_config, "secure", "MATRIX_MYSQL_KEY"),
        (
            "maria",
            live_mariadb_only.engine,
            live_mariadb_only.sql_config,
            "secure",
            "MATRIX_MARIA_KEY",
        ),
    )
    tables = {"mssql": "Users", "mysql": "people", "maria": "people"}
    id_columns = {"mssql": "Id", "mysql": "id", "maria": "id"}
    email_columns = {"mssql": "Email", "mysql": "email", "maria": "email"}
    servers: dict[str, Any] = {}
    for alias, engine, source, source_alias, key_name in engines:
        base = {
            "engine": engine,
            "access_level": "all_pii_safe",
            "connection_url": url(source, source_alias),
            "pii_key_env": key_name,
        }
        servers[alias] = {
            **base,
            "pii": {
                "mode": "deny-by-default",
                "exposed_columns": [{"table": tables[alias], "columns": [id_columns[alias]]}],
            },
        }
        servers[f"{alias}_deny"] = {
            **base,
            "pii_key_env": f"{key_name}_DENY",
            "pii": {
                "mode": "deny-by-default",
                "deny": [{"table": tables[alias], "columns": [email_columns[alias]]}],
            },
        }
    path = tmp_path / "deny-by-default.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "servers": servers}), encoding="utf-8")
    keys = {
        "MATRIX_MSSQL_KEY": live_database.pii_key,
        "MATRIX_MYSQL_KEY": live_mysql_only.key,
        "MATRIX_MARIA_KEY": live_mariadb_only.key,
    }
    # Keys must be unique per alias, so each *_deny alias gets a key derived from its sibling's.
    keys |= {f"{name}_DENY": hashlib.sha256(key).digest() for name, key in keys.items()}
    config = load_config(path, {name: base64.b64encode(key).decode() for name, key in keys.items()})
    databases = {
        "mssql": live_database.database,
        "mysql": live_mysql_only.sql_database,
        "maria": live_mariadb_only.sql_database,
    }
    from_clauses = {
        "mssql": f"[{live_database.alpha_schema}].[Users]",
        "mysql": "people",
        "maria": "people",
    }

    async def scenario() -> None:
        async with Client(create_server(config), raise_exceptions=True) as client:
            for alias in ("mssql", "mysql", "maria"):
                source = from_clauses[alias]
                ok = await client.call_tool(
                    "execute_sql",
                    {
                        "server": alias,
                        "database": databases[alias],
                        "sql": (
                            f"SELECT {id_columns[alias]}, {email_columns[alias]} "
                            f"FROM {source} ORDER BY {id_columns[alias]}"
                        ),
                    },
                )
                assert ok.is_error is False, _text(ok)
                content = ok.structured_content
                assert [column["encoding"] for column in content["columns"]] == ["json", "token"]
                cells = [row[1] for row in content["rows"] if row[1] is not None]  # NULL stays null
                assert cells
                assert all(cell.startswith("pii:v1:") for cell in cells)

                denied = await client.call_tool(
                    "execute_sql",
                    {
                        "server": f"{alias}_deny",
                        "database": databases[alias],
                        "sql": f"SELECT {email_columns[alias]} FROM {source}",
                    },
                )
                assert denied.is_error is True
                assert "a denied column cannot be referenced" in _text(denied)

    asyncio.run(scenario())
