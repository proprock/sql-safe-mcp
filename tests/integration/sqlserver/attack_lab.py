"""Writable SQL Server attack fixture (Milestone 2B, task 2.14).

Two disposable databases share one login that is db_owner in both, so a query that escaped the
validator could really change data. Canary tables and PII markers make any escape observable, and
a cursor-level recorder shows exactly which statements reached the driver.
"""

from __future__ import annotations

import base64
import os
import secrets
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

import pytest
from live_support import quote_identifier
from pydantic import SecretStr
from sqlalchemy import Connection, Engine, create_engine, event, text
from sqlalchemy.engine import URL, make_url

from sql_safe_mcp.config import (
    AppConfig,
    PiiConfig,
    PiiRule,
    PiiScopeRule,
    RuntimeConfig,
    ServerConfig,
)
from sql_safe_mcp.db import registry as registry_module
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.service import DatabaseService

USERS = [
    ("marker-email-1", "marker-phone-1", "Alice"),
    ("marker-email-2", "marker-phone-2", "Bob"),
    ("x'; DROP TABLE Canary;--", "marker-phone-3", "Mallory"),
]
FORBIDDEN_ON_THE_WIRE = (
    "DROP ",
    "DELETE ",
    "INSERT ",
    "UPDATE ",
    "TRUNCATE ",
    "EXEC",
    "WAITFOR",
    "OPENROWSET",
    "OPENQUERY",
    " INTO ",
    "xp_cmdshell",
)


@dataclass(slots=True)
class Recorder:
    """Every statement that reaches a cursor, in order, with its bind parameters."""

    statements: list[tuple[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def attach(self, engine: Engine) -> None:
        @event.listens_for(engine, "before_cursor_execute")
        def record(_conn: Any, _cursor: Any, statement: str, parameters: Any, *_: Any) -> None:
            with self._lock:
                self.statements.append((statement, parameters))

    def mark(self) -> int:
        with self._lock:
            return len(self.statements)

    def since(self, mark: int) -> list[tuple[str, Any]]:
        with self._lock:
            return list(self.statements[mark:])


@dataclass(frozen=True, slots=True)
class AttackLab:
    admin_url: URL
    databases: tuple[str, str]
    schema_names: tuple[str, ...]
    config: AppConfig
    service: DatabaseService
    recorder: Recorder
    writer_url: URL
    markers: tuple[str, ...]
    keys: dict[str, bytes]

    def writer_engine(self, database: str) -> Engine:
        return create_engine(self.writer_url.set(database=database))

    def snapshot(self) -> dict[str, Any]:
        """Everything a successful attack could change, read with the writable login."""
        state: dict[str, Any] = {}
        for database in self.databases:
            engine = self.writer_engine(database)
            try:
                with engine.connect() as connection:
                    state[database] = _snapshot_database(connection)
            finally:
                engine.dispose()
        return state


def _snapshot_database(connection: Connection) -> dict[str, Any]:
    objects = connection.execute(
        text(
            "SELECT s.name, o.name, o.type, CONVERT(varchar(30), o.modify_date, 121) "
            "FROM sys.objects o JOIN sys.schemas s ON s.schema_id = o.schema_id "
            "WHERE o.is_ms_shipped = 0 ORDER BY s.name, o.name"
        )
    )
    snapshot: dict[str, Any] = {"objects": [tuple(row) for row in objects.fetchall()]}
    for table in ("Users", "Canary", "Orders", "Contacts"):
        rows = connection.execute(text(f"SELECT * FROM dbo.[{table}] ORDER BY 1"))
        snapshot[table] = [tuple(row) for row in rows.fetchall()]
    snapshot["principals"] = [
        tuple(row)
        for row in connection.execute(
            text("SELECT name, type FROM sys.database_principals WHERE is_fixed_role = 0")
        ).fetchall()
    ]
    return snapshot


def _batch(connection: Connection, statements: list[str]) -> None:
    for statement in statements:
        connection.exec_driver_sql(statement)


def _build_database(admin: Engine, database: str, suffix: str, writer: str) -> None:
    db = quote_identifier(database)
    with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        _batch(connection, [f"CREATE DATABASE {db}"])
    engine = create_engine(admin.url.set(database=database))
    try:
        with engine.begin() as connection:
            _batch(
                connection,
                [
                    "CREATE SCHEMA [sales]",
                    "CREATE TABLE dbo.[Users] ([Id] int IDENTITY(1,1) PRIMARY KEY, "
                    "[Email] nvarchar(100) NOT NULL, [Phone] nvarchar(30) NULL, "
                    "[Name] nvarchar(50) NULL)",
                    "CREATE TABLE dbo.[Orders] ([Id] int IDENTITY(1,1) PRIMARY KEY, "
                    "[UserId] int NOT NULL, [Total] decimal(10,2) NULL)",
                    "CREATE TABLE dbo.[Contacts] ([Id] int PRIMARY KEY, [Email] nvarchar(100))",
                    "CREATE TABLE dbo.[Canary] ([Id] int NOT NULL, [Note] nvarchar(50))",
                    "CREATE TABLE dbo.[Items] ([Id] int NOT NULL)",
                    "CREATE TABLE dbo.[Visits] ([Id] int PRIMARY KEY, [Hits] int NOT NULL)",
                    "CREATE TABLE [sales].[Items] ([Id] int NOT NULL)",
                    f"CREATE USER {quote_identifier(writer)} FOR LOGIN {quote_identifier(writer)}",
                    f"ALTER ROLE db_owner ADD MEMBER {quote_identifier(writer)}",
                    "INSERT INTO dbo.[Canary] VALUES (1, N'canary-" + suffix + "')",
                    "INSERT INTO dbo.[Contacts] VALUES (1, N'contact-" + suffix + "@example.test')",
                    "INSERT INTO dbo.[Items] VALUES (1)",
                    "INSERT INTO dbo.[Visits] VALUES (1, 424242), (2, 515151)",
                    "INSERT INTO [sales].[Items] VALUES (2)",
                ],
            )
            for email, phone, name in USERS:
                connection.exec_driver_sql(
                    "INSERT INTO dbo.[Users] ([Email], [Phone], [Name]) VALUES (?, ?, ?)",
                    (f"{email}-{suffix}" if "'" not in email else email, phone + suffix, name),
                )
            connection.exec_driver_sql(
                "INSERT INTO dbo.[Orders] ([UserId], [Total]) VALUES (1, 12.50), (2, 99.99)"
            )
    finally:
        engine.dispose()


def _pii_server(url: str, key: bytes, key_env: str, databases: tuple[str, str]) -> ServerConfig:
    return ServerConfig(
        engine="sqlserver",
        access_level="all_pii_safe",
        require_tls=False,  # the test container uses a self-signed certificate
        connection_url=SecretStr(url),
        pii_key_env=key_env,
        pii=PiiConfig(
            rules=[
                PiiRule(database="*", schema="dbo", table="Users", columns=["Email", "Phone"]),
                PiiRule(database="*", schema="dbo", table="Visits", columns=["Hits"]),
                PiiRule(database=databases[0], schema="dbo", table="Orders", columns=["Total"]),
            ],
            deny=[PiiScopeRule(schema="dbo", table="Contacts", columns=["*"])],
        ),
        pii_key=SecretStr(base64.b64encode(key).decode()),
    )


@pytest.fixture(scope="module")
def attack_lab() -> Iterator[AttackLab]:
    raw_url = os.environ.get("SQL_SAFE_MCP_TEST_SQLSERVER_URL")
    if not raw_url:
        pytest.skip("SQL_SAFE_MCP_TEST_SQLSERVER_URL is not configured")

    suffix = uuid4().hex[:10]
    databases = (f"SmmAttackA_{suffix}", f"SmmAttackB_{suffix}")
    writer = f"smm_writer_{suffix}"
    password = "Writer!A1" + secrets.token_hex(16)
    admin_url = make_url(raw_url).set(database="master")
    admin = create_engine(admin_url, pool_pre_ping=True)
    writer_url = admin_url.set(username=writer, password=password)
    keys = {"attack": secrets.token_bytes(32), "attack2": secrets.token_bytes(32)}
    monkeypatch = pytest.MonkeyPatch()
    recorder = Recorder()
    real_create_engine = registry_module.create_engine

    def recording_create_engine(*args: Any, **kwargs: Any) -> Engine:
        engine = real_create_engine(*args, **kwargs)
        recorder.attach(engine)
        return engine

    try:
        with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            _batch(
                connection,
                [
                    f"CREATE LOGIN {quote_identifier(writer)} WITH PASSWORD = '{password}', "
                    "CHECK_POLICY = OFF"
                ],
            )
        for database in databases:
            _build_database(admin, database, suffix, writer)

        writer_text = writer_url.render_as_string(hide_password=False)
        config = AppConfig(
            version=1,
            runtime=RuntimeConfig(statement_timeout_seconds=5, max_concurrent_db_operations=4),
            servers={
                alias: _pii_server(writer_text, keys[alias], f"SMM_{alias.upper()}_KEY", databases)
                for alias in ("attack", "attack2")
            },
        )
        monkeypatch.setattr(registry_module, "create_engine", recording_create_engine)
        registry = EngineRegistry(config)
        service = DatabaseService(config, registry)
        markers = tuple(
            [f"{email}-{suffix}" for email, _, _ in USERS if "'" not in email]
            + [phone + suffix for _, phone, _ in USERS]
        )
        yield AttackLab(
            admin_url,
            databases,
            ("dbo", "sales"),
            config,
            service,
            recorder,
            writer_url,
            markers,
            keys,
        )
        registry.dispose()
    finally:
        monkeypatch.undo()
        with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            for database in databases:
                _batch(
                    connection,
                    [
                        f"IF DB_ID('{database}') IS NOT NULL "
                        f"ALTER DATABASE {quote_identifier(database)} "
                        "SET SINGLE_USER WITH ROLLBACK IMMEDIATE",
                        f"DROP DATABASE IF EXISTS {quote_identifier(database)}",
                    ],
                )
            _batch(
                connection,
                [
                    "DECLARE @kill nvarchar(max) = N''; "
                    "SELECT @kill += N'KILL ' + CONVERT(nvarchar(11), session_id) + N';' "
                    f"FROM sys.dm_exec_sessions WHERE login_name = N'{writer}'; "
                    "IF @kill <> N'' EXEC sys.sp_executesql @kill",
                    f"IF EXISTS (SELECT 1 FROM sys.server_principals WHERE name = '{writer}') "
                    f"DROP LOGIN {quote_identifier(writer)}",
                ],
            )
        admin.dispose()
