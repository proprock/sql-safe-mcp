from __future__ import annotations

import base64
import os
import secrets
from collections.abc import Iterator
from dataclasses import dataclass
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import Connection, create_engine
from sqlalchemy.engine import URL, make_url

from sql_safe_mcp.config import AppConfig, PiiConfig, PiiRule, RuntimeConfig, ServerConfig


@dataclass(frozen=True, slots=True)
class LiveDatabase:
    admin_url: URL
    config: AppConfig
    database: str
    restricted_database: str
    alpha_schema: str
    beta_schema: str
    emails: tuple[str, str]
    injection_email: str
    pii_key: bytes
    other_pii_key: bytes


def quote_identifier(value: str) -> str:
    if not value.replace("_", "").isalnum():
        raise ValueError("test identifiers must be alphanumeric with optional underscores")
    return f"[{value}]"


def _url_for(admin_url: URL, login: str, password: str, database: str) -> str:
    return admin_url.set(
        username=login,
        password=password,
        database=database,
    ).render_as_string(hide_password=False)


def _execute_batch(connection: Connection, statements: list[str]) -> None:
    for statement in statements:
        connection.exec_driver_sql(statement)


def _pii_server(url: str, schema: str, key: bytes, key_env: str) -> ServerConfig:
    return ServerConfig(
        engine="sqlserver",
        access_level="all_pii_safe",
        require_tls=False,  # the test container uses a self-signed certificate
        connection_url=SecretStr(url),
        pii_key_env=key_env,
        pii=PiiConfig(
            rules=[PiiRule(database="*", schema=schema, table="Users", columns=["Email"])]
        ),
        pii_key=SecretStr(base64.b64encode(key).decode()),
    )


@pytest.fixture(scope="module")
def live_database() -> Iterator[LiveDatabase]:
    raw_url = os.environ.get("SQL_SAFE_MCP_TEST_SQLSERVER_URL")
    if not raw_url:
        pytest.skip("SQL_SAFE_MCP_TEST_SQLSERVER_URL is not configured")

    suffix = uuid4().hex[:12]
    database = "SqlSafeMcpTests"
    restricted_database = f"smm_scope_{suffix}"
    alpha_schema = f"alpha_{suffix}"
    beta_schema = f"beta_{suffix}"
    app_login = f"smm_app_{suffix}"
    hidden_login = f"smm_hidden_{suffix}"
    denied_login = f"smm_denied_{suffix}"
    app_password = "App!A1" + secrets.token_hex(16)
    hidden_password = "Hidden!A1" + secrets.token_hex(16)
    denied_password = "Denied!A1" + secrets.token_hex(16)
    emails = (f"marker-a-{suffix}@example.test", f"marker-b-{suffix}@example.test")
    injection_email = f"x'; DROP TABLE Canary;--{suffix}"
    pii_key = secrets.token_bytes(32)
    other_pii_key = secrets.token_bytes(32)
    admin_url = make_url(raw_url).set(database="master")
    admin_engine = create_engine(admin_url, pool_pre_ping=True)

    db = quote_identifier(database)
    alpha = quote_identifier(alpha_schema)
    beta = quote_identifier(beta_schema)
    app = quote_identifier(app_login)
    hidden = quote_identifier(hidden_login)
    denied = quote_identifier(denied_login)

    try:
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            _execute_batch(
                connection,
                [
                    f"IF DB_ID('{database}') IS NULL EXEC(N'CREATE DATABASE {db}')",
                    f"CREATE DATABASE {quote_identifier(restricted_database)}",
                    f"ALTER DATABASE {db} SET COMPATIBILITY_LEVEL = 130",
                    f"CREATE LOGIN {app} WITH PASSWORD = '{app_password}', CHECK_POLICY = OFF",
                    f"CREATE LOGIN {hidden} WITH PASSWORD = '{hidden_password}', "
                    "CHECK_POLICY = OFF",
                    f"CREATE LOGIN {denied} WITH PASSWORD = '{denied_password}', "
                    "CHECK_POLICY = OFF",
                    f"CREATE USER {denied} FOR LOGIN {denied}",
                    f"DENY SELECT ON OBJECT::sys.databases TO {denied}",
                ],
            )

        database_admin = create_engine(admin_url.set(database=database), pool_pre_ping=True)
        try:
            with database_admin.begin() as connection:
                _execute_batch(
                    connection,
                    [
                        f"CREATE SCHEMA {alpha} AUTHORIZATION dbo",
                        f"CREATE SCHEMA {beta} AUTHORIZATION dbo",
                        f"CREATE TABLE {alpha}.[Parents] ("
                        "[TenantId] int NOT NULL, [Id] int NOT NULL, "
                        "CONSTRAINT [PK_Parents] PRIMARY KEY ([TenantId], [Id]))",
                        f"CREATE TABLE {alpha}.[Users] ("
                        "[TenantId] int NOT NULL, [Id] bigint IDENTITY(1,1) NOT NULL, "
                        "[ParentId] int NOT NULL, [Email] nvarchar(100) NOT NULL, "
                        "[Amount] decimal(10,2) NULL CONSTRAINT [DF_Users_Amount] DEFAULT ((0)), "
                        "[DisplayKey] AS (concat([TenantId],'-',[Id])) PERSISTED, "
                        "CONSTRAINT [PK_Users] PRIMARY KEY ([TenantId], [Id]), "
                        "CONSTRAINT [FK_Users_Parents] FOREIGN KEY ([TenantId], [ParentId]) "
                        f"REFERENCES {alpha}.[Parents] ([TenantId], [Id]), "
                        "CONSTRAINT [UQ_Users_Email] UNIQUE ([TenantId], [Email]))",
                        f"CREATE INDEX [IX_Users_Email] ON {alpha}.[Users] ([Email])",
                        f"CREATE TABLE {beta}.[Users] ([Id] int NOT NULL PRIMARY KEY)",
                        f"CREATE TABLE {alpha}.[Canary] ([Id] int NOT NULL)",
                        f"CREATE TABLE {alpha}.[ScopedVisible] ([Id] int NOT NULL PRIMARY KEY)",
                        f"CREATE TABLE {alpha}.[Kinds] ([Id] int NOT NULL, [D] date NULL, "
                        "[T] time(3) NULL, [Dt] datetime2(3) NULL, [G] uniqueidentifier NULL, "
                        "[B] varbinary(4) NULL, [F] float NULL, [Flag] bit NULL, [Amt] money NULL)",
                        f"CREATE PROCEDURE {alpha}.[VisibleProc] AS SELECT 1 AS [Value]",
                        f"CREATE PROCEDURE {alpha}.[HiddenProc] AS SELECT 2 AS [Value]",
                        f"CREATE USER {app} FOR LOGIN {app}",
                        f"CREATE USER {hidden} FOR LOGIN {hidden}",
                        f"GRANT CONNECT TO {app}",
                        f"GRANT SELECT ON SCHEMA::{alpha} TO {app}",
                        f"GRANT SELECT ON SCHEMA::{beta} TO {app}",
                        f"GRANT VIEW DEFINITION TO {app}",
                        f"GRANT CONNECT TO {hidden}",
                        f"GRANT SELECT ON OBJECT::{alpha}.[ScopedVisible] TO {hidden}",
                        f"GRANT EXECUTE ON OBJECT::{alpha}.[HiddenProc] TO {hidden}",
                        f"INSERT INTO {alpha}.[Parents] ([TenantId], [Id]) VALUES (1, 1), (1, 2)",
                        f"INSERT INTO {alpha}.[Canary] ([Id]) VALUES (1)",
                        f"INSERT INTO {alpha}.[Kinds] VALUES (1, '2024-02-29', '01:02:03.004', "
                        "'2024-02-29T13:14:15.123', '12345678-1234-5678-1234-567812345678', "
                        "0x00FF10, 1.5, 1, 12.3400), (2, NULL, NULL, NULL, NULL, NULL, NULL, "
                        "NULL, NULL)",
                    ],
                )
                for index, email in enumerate((*emails, injection_email), start=1):
                    connection.exec_driver_sql(
                        f"INSERT INTO {alpha}.[Users] ([TenantId], [ParentId], [Email], [Amount]) "
                        "VALUES (1, ?, ?, ?)",
                        (1 if index < 3 else 2, email, None if index == 2 else index),
                    )
        finally:
            database_admin.dispose()

        config = AppConfig(
            version=1,
            runtime=RuntimeConfig(
                statement_timeout_seconds=2,
                max_concurrent_db_operations=4,
                pool_size=2,
                max_overflow=2,
                engine_cache_size=8,
            ),
            servers={
                "secure": _pii_server(
                    _url_for(admin_url, app_login, app_password, "master"),
                    alpha_schema,
                    pii_key,
                    "SMM_SECURE_KEY",
                ),
                "secure2": _pii_server(
                    _url_for(admin_url, app_login, app_password, "master"),
                    alpha_schema,
                    other_pii_key,
                    "SMM_SECURE2_KEY",
                ),
                "legacy": ServerConfig(
                    engine="sqlserver",
                    access_level="meta_and_code",
                    connection_url=SecretStr(
                        _url_for(admin_url, app_login, app_password, "master")
                    ),
                ),
                "hidden": ServerConfig(
                    engine="sqlserver",
                    access_level="meta_and_code",
                    connection_url=SecretStr(
                        _url_for(admin_url, hidden_login, hidden_password, "master")
                    ),
                ),
                "denied": ServerConfig(
                    engine="sqlserver",
                    connection_url=SecretStr(
                        _url_for(admin_url, denied_login, denied_password, "master")
                    ),
                ),
            },
        )
        yield LiveDatabase(
            admin_url,
            config,
            database,
            restricted_database,
            alpha_schema,
            beta_schema,
            emails,
            injection_email,
            pii_key,
            other_pii_key,
        )
    finally:
        admin_engine.dispose()
        cleanup_engine = create_engine(admin_url, pool_pre_ping=True)
        database_cleanup_engine = create_engine(
            admin_url.set(database=database), pool_pre_ping=True
        )
        try:
            with cleanup_engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as connection:
                _execute_batch(
                    connection,
                    [
                        "DECLARE @kill nvarchar(max) = N''; "
                        "SELECT @kill += N'KILL ' + CONVERT(nvarchar(11), session_id) + N';' "
                        "FROM sys.dm_exec_sessions WHERE login_name IN "
                        f"(N'{app_login}', N'{hidden_login}', N'{denied_login}'); "
                        "IF @kill <> N'' EXEC sys.sp_executesql @kill",
                    ],
                )
            with database_cleanup_engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as connection:
                _execute_batch(
                    connection,
                    [
                        f"DROP PROCEDURE IF EXISTS {alpha}.[VisibleProc]",
                        f"DROP PROCEDURE IF EXISTS {alpha}.[HiddenProc]",
                        f"DROP TABLE IF EXISTS {alpha}.[Kinds]",
                        f"DROP TABLE IF EXISTS {alpha}.[Canary]",
                        f"DROP TABLE IF EXISTS {alpha}.[ScopedVisible]",
                        f"DROP TABLE IF EXISTS {beta}.[Users]",
                        f"DROP TABLE IF EXISTS {alpha}.[Users]",
                        f"DROP TABLE IF EXISTS {alpha}.[Parents]",
                        f"IF USER_ID('{app_login}') IS NOT NULL DROP USER {app}",
                        f"IF USER_ID('{hidden_login}') IS NOT NULL DROP USER {hidden}",
                        f"IF SCHEMA_ID('{beta_schema}') IS NOT NULL DROP SCHEMA {beta}",
                        f"IF SCHEMA_ID('{alpha_schema}') IS NOT NULL DROP SCHEMA {alpha}",
                    ],
                )
            with cleanup_engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as connection:
                _execute_batch(
                    connection,
                    [
                        f"IF USER_ID('{denied_login}') IS NOT NULL DROP USER {denied}",
                        "IF EXISTS (SELECT 1 FROM sys.server_principals "
                        f"WHERE name = '{app_login}') "
                        f"DROP LOGIN {app}",
                        "IF EXISTS (SELECT 1 FROM sys.server_principals "
                        f"WHERE name = '{hidden_login}') "
                        f"DROP LOGIN {hidden}",
                        "IF EXISTS (SELECT 1 FROM sys.server_principals "
                        f"WHERE name = '{denied_login}') "
                        f"DROP LOGIN {denied}",
                        f"DROP DATABASE IF EXISTS {quote_identifier(restricted_database)}",
                    ],
                )
        finally:
            database_cleanup_engine.dispose()
            cleanup_engine.dispose()
