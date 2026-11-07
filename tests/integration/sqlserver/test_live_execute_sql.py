from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import pytest
from live_support import LiveDatabase
from mcp import Client
from mcp_types import TextContent
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from sql_safe_mcp.mcp_server import create_server
from sql_safe_mcp.security.tokens import TokenCodec

pytestmark = pytest.mark.integration


def call(live: LiveDatabase, server: str, sql: str, **extra: Any) -> tuple[bool, Any]:
    """Run execute_sql through a real MCP client; return (is_error, content or error text)."""

    async def scenario() -> tuple[bool, Any]:
        async with Client(create_server(live.config), raise_exceptions=True) as client:
            result = await client.call_tool(
                "execute_sql",
                {"server": server, "database": live.database, "sql": sql, **extra},
            )
            if result.is_error:
                content = result.content[0]
                assert isinstance(content, TextContent)
                return True, content.text
            return False, result.structured_content

    return asyncio.run(scenario())


def ok(live: LiveDatabase, sql: str, server: str = "secure", **extra: Any) -> dict[str, Any]:
    is_error, content = call(live, server, sql, **extra)
    assert is_error is False, content
    return content


def rejected(
    live: LiveDatabase, sql: str, code: str = "QUERY_REJECTED", server: str = "secure"
) -> None:
    is_error, content = call(live, server, sql)
    assert is_error is True
    assert f"[{code}]" in content, content


def table(live: LiveDatabase, name: str, schema: str | None = None) -> str:
    return f"[{schema or live.alpha_schema}].[{name}]"


def canary_state(live: LiveDatabase) -> tuple[int, int]:
    """(canary rows, tables in the alpha schema) read with the admin login."""
    engine = create_engine(live.admin_url.set(database=live.database))
    try:
        with engine.connect() as connection:
            rows = connection.execute(text(f"SELECT COUNT(*) FROM {table(live, 'Canary')}"))
            canary_rows = int(rows.scalar_one())
            tables = connection.execute(
                text("SELECT COUNT(*) FROM sys.tables WHERE schema_id = SCHEMA_ID(:s)"),
                {"s": live.alpha_schema},
            )
            return canary_rows, int(tables.scalar_one())
    finally:
        engine.dispose()


def codec(live: LiveDatabase, alias: str = "secure") -> TokenCodec:
    key = live.pii_key if alias == "secure" else live.other_pii_key
    return TokenCodec(alias, key)


def token_for(live: LiveDatabase, value: str, alias: str = "secure") -> str:
    return codec(live, alias).encrypt(value)


def test_live_projection_tokenizes_protected_columns(
    live_database: LiveDatabase, caplog: pytest.LogCaptureFixture
) -> None:
    live = live_database
    with caplog.at_level(logging.DEBUG):
        content = ok(
            live,
            f"SELECT Id, Email, Amount FROM {table(live, 'Users')} WHERE TenantId = 1 ORDER BY Id",
        )
    assert content["row_count"] == 3
    assert content["truncated"] is False
    columns = {c["name"]: c for c in content["columns"]}
    assert columns["Email"]["protected"] is True
    assert columns["Email"]["encoding"] == "token"
    assert columns["Amount"]["encoding"] == "decimal"
    assert columns["Id"]["protected"] is False
    tokens = [row[1] for row in content["rows"]]
    assert all(item.startswith("pii:v1:") for item in tokens)
    assert [codec(live).decrypt(item) for item in tokens] == [*live.emails, live.injection_email]
    assert content["rows"][1][2] is None
    serialized = json.dumps(content) + caplog.text
    for marker in (*live.emails, live.injection_email):
        assert marker not in serialized


def test_live_token_predicates_round_trip(live_database: LiveDatabase) -> None:
    live = live_database
    first, second = (token_for(live, email) for email in live.emails)
    users = table(live, "Users")
    one = ok(live, f"SELECT Id, Email FROM {users} WHERE Email = '{first}'")
    assert one["row_count"] == 1
    assert codec(live).decrypt(one["rows"][0][1]) == live.emails[0]
    both = ok(live, f"SELECT Id FROM {users} WHERE Email IN ('{first}', '{second}')")
    assert both["row_count"] == 2
    counted = ok(live, f"SELECT COUNT(*) FROM {users} WHERE Email = '{second}'")
    assert counted["rows"] == [[1]]
    assert counted["columns"][0]["source"] is None


def test_live_injection_payload_is_a_bind_value_and_canary_is_untouched(
    live_database: LiveDatabase,
) -> None:
    live = live_database
    before = canary_state(live)
    payload = token_for(live, live.injection_email)
    result = ok(live, f"SELECT Id FROM {table(live, 'Users')} WHERE Email = '{payload}'")
    assert result["row_count"] == 1
    assert canary_state(live) == before


def test_live_tokens_do_not_cross_aliases(live_database: LiveDatabase) -> None:
    live = live_database
    users = table(live, "Users")
    foreign = token_for(live, live.emails[0], "secure")
    rejected(
        live,
        f"SELECT Id FROM {users} WHERE Email = '{foreign}'",
        "INVALID_PII_TOKEN",
        server="secure2",
    )
    issued = ok(live, f"SELECT Email FROM {users}", server="secure2")
    rejected(
        live,
        f"SELECT Id FROM {users} WHERE Email = '{issued['rows'][0][0]}'",
        "INVALID_PII_TOKEN",
        server="secure",
    )


def test_live_rejected_queries_change_nothing(live_database: LiveDatabase) -> None:
    live = live_database
    before = canary_state(live)
    users = table(live, "Users")
    canary = table(live, "Canary")
    statements = [
        f"DELETE FROM {canary}",
        f"UPDATE {canary} SET Id = 2",
        f"INSERT INTO {canary} VALUES (9)",
        f"DROP TABLE {canary}",
        f"SELECT 1; DROP TABLE {canary}",
        f"SELECT Id FROM {canary}; DELETE FROM {canary}",
        f"SELECT Id INTO [{live.alpha_schema}].[Copy] FROM {canary}",
        f"SELECT Id FROM {users} WHERE Email = 'plain@example.test'",
        f"SELECT Id FROM {users} ORDER BY Email",
        f"SELECT u.Email FROM {users} u JOIN {users} v ON u.Email = v.Email",
        f"WITH x AS (SELECT Id FROM {canary}) SELECT Id FROM x",
        f"SELECT Id FROM {users} WHERE Id IN (SELECT Id FROM {canary})",
        f"SELECT Id FROM {canary} UNION SELECT Id FROM {canary}",
        f"SELECT LOWER(Email) FROM {users}",
        "SELECT * FROM master.sys.objects",
        "SELECT * FROM sys.databases",
        "SELECT * FROM INFORMATION_SCHEMA.TABLES",
        "SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')",
        f"SELECT Id FROM {canary} OPTION (MAXDOP 1)",
        f"SELECT Id FROM {canary} WITH (NOLOCK)",
        "EXEC sp_who",
        "WAITFOR DELAY '0:0:5'",
    ]
    for sql in statements:
        is_error, content = call(live, "secure", sql)
        assert is_error is True, sql
        assert "[QUERY_REJECTED]" in content, (sql, content)
    assert canary_state(live) == before


def test_live_schema_ambiguity_and_qualification(live_database: LiveDatabase) -> None:
    live = live_database
    rejected(live, "SELECT Id FROM Users")
    alpha = ok(live, f"SELECT Id FROM {table(live, 'Users')}")
    beta = ok(live, f"SELECT Id FROM {table(live, 'Users', live.beta_schema)}")
    assert alpha["row_count"] == 3
    assert beta["row_count"] == 0
    lowered = ok(live, f"SELECT id FROM [{live.alpha_schema.upper()}].[users]")
    assert lowered["columns"][0]["name"] == "Id"


def test_live_row_cap_and_truncation(live_database: LiveDatabase) -> None:
    live = live_database
    users = table(live, "Users")
    capped = ok(live, f"SELECT Id FROM {users}", max_rows=2)
    assert (capped["row_count"], capped["truncated"]) == (2, True)
    exact = ok(live, f"SELECT Id FROM {users}", max_rows=3)
    assert (exact["row_count"], exact["truncated"]) == (3, False)
    top = ok(live, f"SELECT TOP 1 Id FROM {users}", max_rows=3)
    assert (top["row_count"], top["truncated"]) == (1, False)
    is_error, content = call(live, "secure", f"SELECT Id FROM {users}", max_rows=0)
    assert is_error and "[INVALID_ARGUMENT]" in content
    is_error, content = call(live, "secure", f"SELECT Id FROM {users}", max_rows=10_000_000)
    assert is_error and "[RESULT_LIMIT_EXCEEDED]" in content


def test_live_native_type_encodings(live_database: LiveDatabase) -> None:
    live = live_database
    content = ok(live, f"SELECT * FROM {table(live, 'Kinds')} ORDER BY Id")
    encodings = {c["name"]: c["encoding"] for c in content["columns"]}
    assert encodings == {
        "Id": "json",
        "D": "date",
        "T": "time",
        "Dt": "datetime",
        "G": "json",  # pyodbc returns uniqueidentifier as str
        "B": "base64",
        "F": "json",
        "Flag": "json",
        "Amt": "decimal",
    }
    full, empty = content["rows"]
    assert full[1:] == [
        "2024-02-29",
        "01:02:03.004000",
        "2024-02-29T13:14:15.123000",
        "12345678-1234-5678-1234-567812345678",
        "AP8Q",
        1.5,
        True,
        "12.3400",
    ]
    assert empty[1:] == [None] * 8


def test_live_metadata_alias_is_denied(live_database: LiveDatabase) -> None:
    live = live_database
    rejected(live, f"SELECT Id FROM {table(live, 'Users')}", "ACCESS_LEVEL_DENIED", "legacy")


def test_live_missing_table_and_invalid_database_are_safe_errors(
    live_database: LiveDatabase,
) -> None:
    live = live_database
    rejected(live, "SELECT Id FROM [dbo].[DefinitelyMissing]")
    password = make_url(live.config.servers["secure"].connection_url.get_secret_value()).password

    async def scenario() -> str:
        async with Client(create_server(live.config), raise_exceptions=True) as client:
            result = await client.call_tool(
                "execute_sql",
                {"server": "secure", "database": "NoSuchDb_x", "sql": "SELECT 1"},
            )
            assert result.is_error is True
            item = result.content[0]
            assert isinstance(item, TextContent)
            return item.text

    message = asyncio.run(scenario())
    assert "ODBC" not in message
    assert "Traceback" not in message
    assert password is not None
    assert password not in message


def test_live_concurrent_executions_are_isolated(live_database: LiveDatabase) -> None:
    live = live_database
    users = table(live, "Users")

    async def scenario() -> list[Any]:
        async with Client(create_server(live.config), raise_exceptions=True) as client:
            calls = [
                client.call_tool(
                    "execute_sql",
                    {
                        "server": "secure",
                        "database": live.database,
                        "sql": f"SELECT Id, Email FROM {users} WHERE TenantId = 1",
                    },
                )
                for _ in range(12)
            ]
            return list(await asyncio.gather(*calls))

    results = asyncio.run(scenario())
    assert all(result.is_error is False for result in results)
    assert {result.structured_content["row_count"] for result in results} == {3}


def test_live_token_of_another_type_is_rejected_before_the_database(
    live_database: LiveDatabase, caplog: pytest.LogCaptureFixture
) -> None:
    live = live_database
    users = table(live, "Users")
    wrong = codec(live).encrypt(424242)
    before = canary_state(live)
    rejected(live, f"SELECT Id FROM {users} WHERE Email = '{wrong}'")
    rejected(live, f"SELECT Id FROM {users} WHERE Email IN ('{wrong}')")
    assert "424242" not in caplog.text
    assert canary_state(live) == before
