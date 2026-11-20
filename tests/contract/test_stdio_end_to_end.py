"""End-to-end check over the real stdio transport: the server runs as a subprocess.

The unreachable database is a loopback port that is bound but never listening, so a connect is
refused deterministically without DNS, network access or an ODBC driver. One subprocess session
serves all tests in this module; each test asserts one property of that run.
"""

from __future__ import annotations

import asyncio
import re
import socket
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import pytest
from mcp import ClientSession, StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent

HOST = "127.0.0.1"
PASSWORD = "pw-marker-7531"
SESSION_TIMEOUT_SECONDS = 60
REFERENCE = re.compile(r"Reference: ([0-9a-f]{32})")


@dataclass(frozen=True)
class Session:
    servers: CallToolResult
    tables: CallToolResult
    stderr: str

    def tables_text(self) -> str:
        content = self.tables.content[0]
        assert isinstance(content, TextContent)
        return content.text


@contextmanager
def _refused_port() -> Iterator[int]:
    # Bound, not listening: connecting to it is refused until the socket is closed.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind((HOST, 0))
        yield reserved.getsockname()[1]


def _config(port: int) -> str:
    return f"""version: 1
servers:
  catalog:
    engine: mysql
    connection_url: mysql+pymysql://user:{PASSWORD}@{HOST}:{port}/shop
"""


async def _converse(config: Path, errlog: TextIO) -> tuple[CallToolResult, CallToolResult]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "sql_safe_mcp", "--config", str(config)],
    )
    async with asyncio.timeout(SESSION_TIMEOUT_SECONDS):
        async with (
            stdio_client(parameters, errlog=errlog) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            servers = await session.call_tool("list_servers")
            tables = await session.call_tool(
                "list_tables", {"server": "catalog", "database": "shop"}
            )
    return servers, tables


@pytest.fixture(scope="module")
def session(tmp_path_factory: pytest.TempPathFactory) -> Session:
    base = tmp_path_factory.mktemp("stdio")
    config = base / "config.yaml"
    errlog_path = base / "stderr.txt"
    with _refused_port() as port:
        config.write_text(_config(port), encoding="utf-8")
        with errlog_path.open("w", encoding="utf-8") as errlog:
            servers, tables = asyncio.run(_converse(config, errlog))
    return Session(servers, tables, errlog_path.read_text(encoding="utf-8"))


def test_list_servers_returns_the_configured_alias(session: Session) -> None:
    assert session.servers.is_error is False
    assert session.servers.structured_content == {
        "servers": [{"name": "catalog", "engine": "mysql", "access_level": "metadata"}]
    }


def test_unreachable_database_is_a_tool_error_not_a_protocol_failure(session: Session) -> None:
    assert session.tables.is_error is True
    assert session.tables_text().startswith("Error executing tool list_tables: [CONNECTION_FAILED]")


def test_error_text_and_stderr_never_contain_the_password_or_host(session: Session) -> None:
    tool_text = session.tables_text()
    for leaked in (PASSWORD, HOST):
        assert leaked not in tool_text
        assert leaked not in session.stderr


def test_stderr_records_this_failed_call_with_its_reference(session: Session) -> None:
    # Positive control for the leak check: without this, an empty or unrelated stderr would pass.
    # Rich wraps log lines, so whitespace is normalised before looking for the reference.
    match = REFERENCE.search(session.tables_text())
    assert match is not None
    flat = re.sub(r"\s+", "", session.stderr)
    assert match.group(1) in flat
    assert "code=CONNECTION_FAILED" in flat
    assert "operation=list_tables" in flat
