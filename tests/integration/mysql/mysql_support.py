from __future__ import annotations

import base64
import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url

from sql_safe_mcp.config import AppConfig, PiiConfig, PiiRule, RuntimeConfig, ServerConfig

Engine = Literal["mysql", "mariadb"]

_ENV = {
    "mysql": "SQL_SAFE_MCP_TEST_MYSQL_URL",
    "mariadb": "SQL_SAFE_MCP_TEST_MARIADB_URL",
}


@dataclass(frozen=True, slots=True)
class LiveMySql:
    engine: Engine
    admin_url: URL
    config: AppConfig
    database: str
    sql_config: AppConfig  # two all_pii_safe aliases with different keys over `sql_database`
    sql_database: str
    logins: dict[str, tuple[str, str]]
    key: bytes
    other_key: bytes


def build_config(
    engine: Engine, admin_url: URL, database: str, logins: dict[str, tuple[str, str]], timeout: int
) -> AppConfig:
    return AppConfig(
        version=1,
        runtime=RuntimeConfig(statement_timeout_seconds=timeout, pool_timeout_seconds=5),
        servers={
            alias: ServerConfig(
                engine=engine,
                access_level="meta_and_code" if alias in {"app", "hidden"} else "metadata",
                connection_url=SecretStr(
                    admin_url.set(
                        username=login, password=password, database=database
                    ).render_as_string(hide_password=False)
                ),
            )
            for alias, (login, password) in logins.items()
        },
    )


def build_sql_config(
    engine: Engine, admin_url: URL, database: str, login: tuple[str, str], keys: dict[str, bytes]
) -> AppConfig:
    url = admin_url.set(username=login[0], password=login[1], database=database)
    return AppConfig(
        version=1,
        runtime=RuntimeConfig(statement_timeout_seconds=5, pool_timeout_seconds=5),
        servers={
            alias: ServerConfig(
                engine=engine,
                access_level="all_pii_safe",
                connection_url=SecretStr(url.render_as_string(hide_password=False)),
                pii_key_env=f"KEY_{alias.upper()}",
                pii=PiiConfig(
                    rules=[
                        PiiRule(database="*", table="people", columns=["email"]),
                        PiiRule(database="*", table="visits", columns=["hits"]),
                    ]
                ),
                pii_key=SecretStr(base64.b64encode(key).decode()),
            )
            for alias, key in keys.items()
        },
    )


def _run(url: URL, statements: Sequence[str | tuple[str, tuple]]) -> None:
    # Raw DBAPI cursor: SQLAlchemy would apply %-formatting to statements such as '%' hosts.
    engine = create_engine(url)
    try:
        raw = engine.raw_connection()
        try:
            cursor = raw.cursor()
            for statement in statements:
                if isinstance(statement, tuple):
                    cursor.execute(*statement)
                else:
                    cursor.execute(statement)
            raw.commit()
        finally:
            raw.close()
    finally:
        engine.dispose()


@contextmanager
def live_server(engine: Engine) -> Iterator[LiveMySql]:
    raw_url = os.environ.get(_ENV[engine])
    if not raw_url:
        pytest.skip(f"{_ENV[engine]} is not configured")
    admin_url = make_url(raw_url)

    suffix = uuid4().hex[:12]
    database = f"smm_{suffix}"
    logins = {
        "app": (f"smm_app_{suffix}", uuid4().hex),
        "hidden": (f"smm_hidden_{suffix}", uuid4().hex),
        "denied": (f"smm_denied_{suffix}", uuid4().hex),
    }
    grants = {
        "app": f"GRANT ALL ON `{database}`.* TO '{{login}}'@'%'",
        "hidden": f"GRANT EXECUTE ON `{database}`.* TO '{{login}}'@'%'",
    }
    sql_database = f"smm_sql_{suffix}"
    key, other_key = uuid4().bytes * 2, uuid4().bytes * 2
    cleanup = [
        f"DROP DATABASE IF EXISTS `{database}`",
        f"DROP DATABASE IF EXISTS `{sql_database}`",
    ] + [f"DROP USER IF EXISTS '{login}'@'%'" for login, _ in logins.values()]
    _run(admin_url, cleanup)
    try:
        app_login = logins["app"][0]
        setup: list[str | tuple[str, tuple]] = [f"CREATE DATABASE `{database}`"]
        for alias, (login, password) in logins.items():
            setup.append(f"CREATE USER '{login}'@'%' IDENTIFIED BY '{password}'")
            if alias in grants:
                setup.append(grants[alias].format(login=login))
        setup += [
            f"CREATE DATABASE `{sql_database}`",
            f"GRANT ALL ON `{sql_database}`.* TO '{app_login}'@'%'",
            f"""CREATE TABLE `{sql_database}`.`people` (
                id INT NOT NULL PRIMARY KEY,
                name VARCHAR(200) NULL,
                email VARCHAR(120) NULL,
                born DATE NULL,
                seen DATETIME(3) NULL,
                at TIME NULL,
                amount DECIMAL(10, 2) NULL,
                raw BLOB NULL,
                flag BIT(1) NULL,
                yr YEAR NULL,
                score DOUBLE NULL,
                tags SET('a', 'b') NULL,
                doc JSON NULL
            ) ENGINE=InnoDB""",
            f"CREATE TABLE `{sql_database}`.`canary` (id INT PRIMARY KEY)",
            f"INSERT INTO `{sql_database}`.`canary` VALUES (1), (2), (3)",
            f"CREATE TABLE `{sql_database}`.`visits` (id INT PRIMARY KEY, hits INT NOT NULL)",
            f"INSERT INTO `{sql_database}`.`visits` VALUES (1, 424242), (2, 515151)",
        ]
        people = f"INSERT INTO `{sql_database}`.`people` (id, name, email) VALUES (%s, %s, %s)"
        setup += [
            (people, (1, "alice", "a@example.com")),
            (people, (2, "100%", "b@example.com")),
            (people, (3, "\\' OR 1=1 -- ", "x'; DROP TABLE canary;--")),
            (people, (4, "dora", None)),
            (people, (6, "long time", None)),
            (f"UPDATE `{sql_database}`.`people` SET at = '100:00:00' WHERE id = 6", ()),
            (
                f"INSERT INTO `{sql_database}`.`people` "
                "(id, name, email, born, seen, at, amount, raw, flag, yr, score, tags, doc) "
                "VALUES (5, 'types', 'c@example.com', '2024-02-03', '2024-02-03 04:05:06.789', "
                "'07:08:09', 12345.67, x'00ff', b'1', 2024, 1.5, 'a,b', "
                "'{\"k\": 1}')",
                (),
            ),
        ]
        setup += [
            f"""CREATE TABLE `{database}`.`users` (
                tenant_id INT NOT NULL,
                id BIGINT NOT NULL,
                parent_id BIGINT NULL,
                email VARCHAR(120) NOT NULL,
                amount DECIMAL(12, 2) NULL,
                created DATETIME(3) NULL,
                PRIMARY KEY (tenant_id, id),
                UNIQUE KEY uq_users_email (tenant_id, email),
                KEY ix_users_email (email),
                CONSTRAINT fk_users_parent FOREIGN KEY (tenant_id, parent_id)
                    REFERENCES `{database}`.`users` (tenant_id, id)
            ) ENGINE=InnoDB""",
            f"CREATE TABLE `{database}`.`audit_events` (id INT PRIMARY KEY, note TEXT)",
            f"GRANT SELECT ON `{database}`.`users` TO '{logins['hidden'][0]}'@'%'",
            # Only the definer sees a routine body; the other logins get NULL.
            f"CREATE DEFINER='{app_login}'@'%' PROCEDURE `{database}`.`visible_proc`() "
            "BEGIN SELECT 1; END",
            f"CREATE DEFINER='{app_login}'@'%' PROCEDURE `{database}`.`other_proc`() "
            "BEGIN SELECT 2; END",
        ]
        _run(admin_url, setup)
        yield LiveMySql(
            engine=engine,
            admin_url=admin_url,
            config=build_config(engine, admin_url, database, logins, timeout=2),
            database=database,
            sql_config=build_sql_config(
                engine,
                admin_url,
                sql_database,
                logins["app"],
                {"secure": key, "secure2": other_key},
            ),
            sql_database=sql_database,
            logins=logins,
            key=key,
            other_key=other_key,
        )
    finally:
        _run(admin_url, cleanup)


@pytest.fixture(scope="module", params=["mysql", "mariadb"])
def live_mysql(request: pytest.FixtureRequest) -> Iterator[LiveMySql]:
    with live_server(request.param) as live:
        yield live


@pytest.fixture(scope="module")
def live_mysql_only() -> Iterator[LiveMySql]:
    with live_server("mysql") as live:
        yield live


@pytest.fixture(scope="module")
def live_mariadb_only() -> Iterator[LiveMySql]:
    with live_server("mariadb") as live:
        yield live
