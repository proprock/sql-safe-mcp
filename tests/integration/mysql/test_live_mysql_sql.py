from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import pytest
import yaml
from mcp import Client
from mcp_types import TextContent
from mysql_support import LiveMySql, kill_running_queries, live_mysql, running_queries
from sqlalchemy import create_engine

from sql_safe_mcp.config import PiiConfig, RuntimeConfig
from sql_safe_mcp.mcp_server import create_server
from sql_safe_mcp.pii_audit import collect_catalog, verify_pii_rules
from sql_safe_mcp.pii_scaffold import collect_scaffold_catalog, render_scaffold
from sql_safe_mcp.security.tokens import TokenCodec

pytestmark = pytest.mark.integration

__all__ = ["live_mysql"]

EMAILS = {1: "a@example.com", 2: "b@example.com", 3: "x'; DROP TABLE canary;--", 5: "c@example.com"}
BACKSLASH_NAME_SQL = r"'\\\' OR 1=1 -- '"  # the MySQL literal for the value  \' OR 1=1 --


def _codec(live: LiveMySql, alias: str = "secure") -> TokenCodec:
    return TokenCodec(alias, live.key if alias == "secure" else live.other_key)


def _token(live: LiveMySql, value: str, alias: str = "secure") -> str:
    return _codec(live, alias).encrypt(value)


def _error_text(result: Any) -> str:
    assert result.is_error is True
    content = result.content[0]
    assert isinstance(content, TextContent)
    return content.text


async def _sql(client: Client, live: LiveMySql, sql: str, **extra: Any) -> Any:
    return await client.call_tool(
        "execute_sql",
        {"server": "secure", "database": live.sql_database, "sql": sql, **extra},
    )


def _ids(result: Any) -> list[int]:
    assert result.is_error is False, result.content
    return [row[0] for row in result.structured_content["rows"]]


def _canary(live: LiveMySql) -> list[tuple[Any, ...]]:
    engine = create_engine(live.admin_url.set(database=live.sql_database))
    try:
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor()
            cursor.execute("SELECT id FROM canary ORDER BY id")
            return [tuple(row) for row in cursor.fetchall()]
        finally:
            raw.close()
    finally:
        engine.dispose()


def _global_sql_mode(live: LiveMySql, new_mode: str | None = None) -> str:
    engine = create_engine(live.admin_url)
    try:
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor()
            cursor.execute("SELECT @@GLOBAL.sql_mode")
            row = cursor.fetchone()
            assert row is not None
            current = str(row[0])
            if new_mode is not None:
                cursor.execute("SET GLOBAL sql_mode = %s", (new_mode,))
            return current
        finally:
            raw.close()
    finally:
        engine.dispose()


def test_live_tool_list_and_tokenized_projection(
    live_mysql: LiveMySql, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)

    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            tools = {tool.name for tool in (await client.list_tools()).tools}
            assert "execute_sql" in tools

            result = await _sql(client, live_mysql, "SELECT id, name, email FROM people")
            payload = result.structured_content
            assert [column["name"] for column in payload["columns"]] == ["id", "name", "email"]
            assert [column["encoding"] for column in payload["columns"]] == [
                "json",
                "json",
                "token",
            ]
            assert [column["protected"] for column in payload["columns"]] == [False, False, True]
            assert payload["columns"][2]["source"] == {
                "schema": None,
                "table": "people",
                "column": "email",
            }
            rows = {row[0]: row for row in payload["rows"]}
            assert rows[4][2] is None
            codec = _codec(live_mysql)
            for row_id, email in EMAILS.items():
                assert codec.decrypt(rows[row_id][2]) == email
            assert payload["truncated"] is False

    asyncio.run(scenario())
    text = caplog.text
    assert not any(email in text for email in EMAILS.values())
    assert "pii:v1:" not in text


def test_live_token_predicates_and_injection_payload_stay_binds(live_mysql: LiveMySql) -> None:
    before = _canary(live_mysql)

    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            first = _token(live_mysql, EMAILS[1])
            second = _token(live_mysql, EMAILS[2])
            payload = _token(live_mysql, EMAILS[3])

            assert _ids(
                await _sql(client, live_mysql, f"SELECT id FROM people WHERE email = '{first}'")
            ) == [1]
            assert sorted(
                _ids(
                    await _sql(
                        client,
                        live_mysql,
                        f"SELECT id FROM people WHERE email IN ('{first}', '{second}')",
                    )
                )
            ) == [1, 2]
            count = await _sql(
                client,
                live_mysql,
                f"SELECT COUNT(*) FROM people WHERE email IN ('{first}', '{second}')",
            )
            assert count.structured_content["rows"] == [[2]]
            assert _ids(
                await _sql(client, live_mysql, f"SELECT id FROM people WHERE email = '{payload}'")
            ) == [3]

    asyncio.run(scenario())
    assert _canary(live_mysql) == before == [(1,), (2,), (3,)]


def test_live_percent_and_backslash_literals_reach_the_server_intact(
    live_mysql: LiveMySql,
) -> None:
    queries = {
        "SELECT id FROM people WHERE name = '100%'": [2],
        f"SELECT id FROM people WHERE name = {BACKSLASH_NAME_SQL}": [3],
        f"SELECT id FROM people WHERE name = {BACKSLASH_NAME_SQL} OR name = 'alice'": [1, 3],
    }

    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            for sql, expected in queries.items():
                assert sorted(_ids(await _sql(client, live_mysql, sql))) == expected, sql
            token = _token(live_mysql, EMAILS[2])
            mixed = await _sql(
                client,
                live_mysql,
                f"SELECT id FROM people WHERE name = '100%' AND email = '{token}'",
            )
            assert _ids(mixed) == [2]

    asyncio.run(scenario())


def test_live_no_backslash_escapes_server_mode_cannot_break_out(live_mysql: LiveMySql) -> None:
    original = _global_sql_mode(live_mysql)
    unsafe = ",".join(part for part in (original, "NO_BACKSLASH_ESCAPES") if part)
    before = _canary(live_mysql)
    _global_sql_mode(live_mysql, unsafe)
    try:

        async def scenario() -> None:
            async with Client(
                create_server(live_mysql.sql_config), raise_exceptions=True
            ) as client:
                result = await _sql(
                    client, live_mysql, f"SELECT id FROM people WHERE name = {BACKSLASH_NAME_SQL}"
                )
                assert _ids(result) == [3]

        asyncio.run(scenario())
    finally:
        _global_sql_mode(live_mysql, original)
    assert _canary(live_mysql) == before


def test_live_native_result_types(live_mysql: LiveMySql) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            result = await _sql(
                client,
                live_mysql,
                "SELECT born, seen, at, amount, raw, flag, yr, score, doc FROM people WHERE id = 5",
            )
            payload = result.structured_content
            assert [column["encoding"] for column in payload["columns"]] == [
                "date",
                "datetime",
                "time",
                "decimal",
                "base64",
                "base64",
                "json",
                "json",
                "json",
            ]
            born, seen, at, amount, raw, flag, yr, score, doc = payload["rows"][0]
            assert (born, at, amount, raw, flag, yr, score) == (
                "2024-02-03",
                "07:08:09",
                "12345.67",
                "AP8=",
                "AQ==",
                2024,
                1.5,
            )
            assert seen.startswith("2024-02-03T04:05:06.789")
            assert json.loads(doc) == {"k": 1}

            tags = await _sql(client, live_mysql, "SELECT tags FROM people WHERE id = 5")
            assert tags.structured_content["rows"] == [["a,b"]]  # SET arrives as text

            long_time = await _sql(client, live_mysql, "SELECT at FROM people WHERE id = 6")
            assert "DATABASE_ERROR" in _error_text(long_time)  # a TIME beyond 24 hours

    asyncio.run(scenario())


def test_live_row_cap_and_truncation(live_mysql: LiveMySql) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            capped = await _sql(client, live_mysql, "SELECT id FROM people ORDER BY id", max_rows=2)
            assert capped.structured_content["row_count"] == 2
            assert capped.structured_content["truncated"] is True
            assert _ids(capped) == [1, 2]
            limited = await _sql(client, live_mysql, "SELECT id FROM people LIMIT 1", max_rows=3)
            assert limited.structured_content["row_count"] == 1
            assert limited.structured_content["truncated"] is False

    asyncio.run(scenario())


REJECTED = [
    "DELETE FROM canary",
    "SELECT id FROM canary; DROP TABLE canary",
    "SELECT id INTO OUTFILE '/tmp/smm' FROM canary",
    "SELECT id FROM canary FOR UPDATE",
    "SELECT SLEEP(5)",
    "SELECT id FROM mysql.user",
    "SELECT id FROM information_schema.tables",
    "SELECT id FROM canary UNION SELECT id FROM people",
    "SELECT id FROM people WHERE email = 'a@example.com'",
    "SELECT id FROM people ORDER BY email",
    "SELECT id FROM people WHERE id IN (SELECT id FROM canary)",
    "WITH t AS (SELECT id FROM canary) SELECT id FROM t",
    "SELECT id FROM canary LIMIT 1, 2",
    "SELECT @@version",
    "TRUNCATE TABLE canary",
]


def test_live_rejected_queries_leave_the_canary_untouched(live_mysql: LiveMySql) -> None:
    before = _canary(live_mysql)

    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            for sql in REJECTED:
                assert "QUERY_REJECTED" in _error_text(await _sql(client, live_mysql, sql)), sql

    asyncio.run(scenario())
    assert _canary(live_mysql) == before == [(1,), (2,), (3,)]


def test_live_tokens_are_isolated_per_alias(live_mysql: LiveMySql) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            own = _token(live_mysql, EMAILS[1], "secure")
            foreign = _token(live_mysql, EMAILS[1], "secure2")
            good = await client.call_tool(
                "execute_sql",
                {
                    "server": "secure2",
                    "database": live_mysql.sql_database,
                    "sql": f"SELECT id FROM people WHERE email = '{foreign}'",
                },
            )
            assert _ids(good) == [1]
            failures = []
            for sql in (
                f"SELECT id FROM people WHERE email = '{own}'",
                "SELECT id FROM people WHERE email = 'pii:v1:AAAA'",
                f"SELECT id FROM people WHERE email = '{foreign[:-8]}'",
            ):
                bad = await client.call_tool(
                    "execute_sql",
                    {"server": "secure2", "database": live_mysql.sql_database, "sql": sql},
                )
                failures.append(_error_text(bad))
            assert all("INVALID_PII_TOKEN" in text for text in failures)
            assert len(set(failures)) == 1

    asyncio.run(scenario())


def test_live_concurrent_execute_sql_calls(live_mysql: LiveMySql) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            token = _token(live_mysql, EMAILS[1])
            results = await asyncio.gather(
                *(
                    _sql(client, live_mysql, f"SELECT id FROM people WHERE email = '{token}'")
                    for _ in range(12)
                )
            )
            assert all(_ids(result) == [1] for result in results)

    asyncio.run(scenario())


def test_live_token_of_another_type_is_rejected_before_the_database(live_mysql: LiveMySql) -> None:
    before = _canary(live_mysql)

    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            wrong = _codec(live_mysql).encrypt(424242)
            result = await _sql(
                client, live_mysql, f"SELECT id FROM people WHERE email = '{wrong}'"
            )
            text = _error_text(result)
            assert "[QUERY_REJECTED]" in text
            assert "424242" not in text

    asyncio.run(scenario())
    assert _canary(live_mysql) == before


def test_live_token_against_an_int_column_must_be_an_int_token(live_mysql: LiveMySql) -> None:
    async def scenario() -> None:
        async with Client(create_server(live_mysql.sql_config), raise_exceptions=True) as client:
            codec = _codec(live_mysql)
            accepted = await _sql(
                client, live_mysql, f"SELECT id FROM visits WHERE hits = '{codec.encrypt(424242)}'"
            )
            assert _ids(accepted) == [1]
            wrong = await _sql(
                client,
                live_mysql,
                f"SELECT id FROM visits WHERE hits = '{codec.encrypt('424242')}'",
            )
            text = _error_text(wrong)
            assert "[QUERY_REJECTED]" in text
            assert "424242" not in text

    asyncio.run(scenario())


def _database_spellings(name: str) -> dict[str, str]:
    """Spellings a caller can send; whatever the server accepts must stay under the rules."""
    fullwidth = {chr(code): chr(code + 0xFEE0) for code in range(0x21, 0x7F)}
    return {
        "other case": name.upper(),
        "one trailing space": f"{name} ",
        "three trailing spaces": f"{name}   ",
        "fullwidth last letter": name[:-1] + fullwidth[name[-1]],
        "trailing ideographic space": f"{name}\u3000",
    }


async def _spelled(live: LiveMySql, server: str, database: str) -> Any:
    async with Client(create_server(live.sql_config), raise_exceptions=True) as client:
        return await client.call_tool(
            "execute_sql",
            {"server": server, "database": database, "sql": "SELECT id, email FROM people"},
        )


@pytest.mark.parametrize("variant", list(_database_spellings("x")))
def test_live_rule_naming_the_database_holds_for_every_spelling(
    live_mysql: LiveMySql, variant: str
) -> None:
    spelling = _database_spellings(live_mysql.sql_database)[variant]
    result = asyncio.run(_spelled(live_mysql, "exact", spelling))
    if result.is_error:
        return  # refusing the spelling is as safe as masking it
    for row in result.structured_content["rows"]:
        assert row[1] is None or str(row[1]).startswith("pii:v1:"), row


@pytest.mark.parametrize("variant", list(_database_spellings("x")))
def test_live_deny_rule_naming_the_database_holds_for_every_spelling(
    live_mysql: LiveMySql, variant: str
) -> None:
    spelling = _database_spellings(live_mysql.sql_database)[variant]
    result = asyncio.run(_spelled(live_mysql, "exact_deny", spelling))
    assert result.is_error is True, result.structured_content


HEAVY_SQL = "SELECT COUNT(*) FROM big a JOIN big b ON a.id <> b.id JOIN big c ON c.id <> a.id"


_DRAIN_DEADLINE_SECONDS = 5


def test_live_server_aborts_a_slow_query_before_the_client_gives_up(live_mysql: LiveMySql) -> None:
    config = live_mysql.sql_config.model_copy(
        update={"runtime": RuntimeConfig(statement_timeout_seconds=1, pool_timeout_seconds=5)}
    )

    async def scenario() -> tuple[Any, float]:
        async with Client(create_server(config), raise_exceptions=True) as client:
            started = time.perf_counter()
            result = await asyncio.wait_for(_sql(client, live_mysql, HEAVY_SQL), timeout=20)
            return result, time.perf_counter() - started

    try:
        result, elapsed = asyncio.run(scenario())
        assert "TIMEOUT" in _error_text(result)
        # The client read_timeout is 6 s here; only the server limit can answer in about 1 s.
        assert elapsed < 4
        deadline = time.monotonic() + _DRAIN_DEADLINE_SECONDS
        while running_queries(live_mysql.admin_url, live_mysql.sql_database):
            assert time.monotonic() < deadline, (
                f"query still running on the server {_DRAIN_DEADLINE_SECONDS} s after TIMEOUT"
            )
            time.sleep(0.25)
    finally:
        kill_running_queries(live_mysql.admin_url, live_mysql.sql_database)


def test_live_engine_set_for_the_other_server_names_the_fix(live_mysql: LiveMySql) -> None:
    swapped = "mariadb" if live_mysql.engine == "mysql" else "mysql"
    wrong = live_mysql.sql_config.model_copy(
        update={
            "servers": {
                alias: server.model_copy(update={"engine": swapped})
                for alias, server in live_mysql.sql_config.servers.items()
            }
        }
    )

    async def scenario() -> Any:
        async with Client(create_server(wrong), raise_exceptions=True) as client:
            return await _sql(client, live_mysql, "SELECT id FROM canary")

    text = _error_text(asyncio.run(scenario()))
    assert "CONFIG_ERROR" in text
    assert f"set engine: {live_mysql.engine}" in text


def test_live_scaffold_drafts_a_section_that_passes_strict_verification(
    live_mysql: LiveMySql,
) -> None:
    config = live_mysql.sql_config
    pii = config.servers["secure"].pii
    assert pii is not None

    catalog = collect_scaffold_catalog(config, "secure", [live_mysql.sql_database.upper()])
    text = render_scaffold("secure", catalog, pii)
    draft = yaml.safe_load(text)

    assert list(catalog.databases) == [live_mysql.sql_database]
    assert all("schema" not in entry for entry in draft["exposed_columns"] + draft["deny"])
    exposed = {entry["table"]: set(entry["columns"]) for entry in draft["exposed_columns"]}
    denied = {entry["table"]: set(entry["columns"]) for entry in draft["deny"]}
    assert {"score", "amount"} <= exposed["people"]
    assert denied["people"] == {"raw"}
    assert "visits" not in exposed  # visits.hits is protected by an existing rule
    assert "# protected by an existing rule:" in text and "visits.hits" in text

    pasted = config.servers["secure"].model_copy(update={"pii": PiiConfig.model_validate(draft)})
    report = verify_pii_rules(
        config.model_copy(update={"servers": {"secure": pasted}}), collect_catalog
    )
    assert report.errors == 0
    assert report.unmatched_rules == 0
