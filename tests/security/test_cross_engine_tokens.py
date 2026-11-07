"""PII tokens never cross server aliases, including across SQL Server, MySQL, and MariaDB."""

from __future__ import annotations

import asyncio
import base64
import itertools
from typing import Any, cast

import pytest
from support import Catalog, SpyConnection, SpyResult, _SpyRegistry
from support_mysql import MysqlCatalog

from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.service import DatabaseService

ENGINES = {"mssql": "sqlserver", "mysql": "mysql", "maria": "mariadb"}
KEYS = {alias: bytes([index]) * 32 for index, alias in enumerate(ENGINES, start=1)}
URLS = {
    "sqlserver": "mssql+pyodbc://u:p@sql/master?driver=x&Encrypt=yes",
    "mysql": "mysql+pymysql://u:p@db/app?ssl_ca=/ca.pem",
    "mariadb": "mysql+pymysql://u:p@db/app?ssl_ca=/ca.pem",
}
QUERY = "SELECT u.Id FROM Users u WHERE u.Email = '{token}'"


def _server(alias: str) -> dict[str, Any]:
    engine = ENGINES[alias]
    rule: dict[str, Any] = {"database": "*", "table": "Users", "columns": ["Email"]}
    if engine == "sqlserver":
        rule["schema"] = "dbo"
    return {
        "engine": engine,
        "access_level": "all_pii_safe",
        "connection_url": URLS[engine],
        "pii_key_env": f"KEY_{alias.upper()}",
        "pii_key": base64.b64encode(KEYS[alias]).decode(),
        "pii": {"rules": [rule]},
    }


def _service(connection: SpyConnection) -> DatabaseService:
    config = AppConfig.model_validate(
        {"version": 1, "servers": {alias: _server(alias) for alias in ENGINES}}
    )
    return DatabaseService(
        config,
        cast(EngineRegistry, _SpyRegistry(connection)),
        catalog_factory=lambda _connection, alias, _database: (
            Catalog() if ENGINES[alias] == "sqlserver" else MysqlCatalog()
        ),
    )


def _run(service: DatabaseService, alias: str, token: str) -> str:
    with pytest.raises(DomainError) as info:
        asyncio.run(service.execute_sql(alias, "app", QUERY.format(token=token)))
    assert info.value.code is ErrorCode.INVALID_PII_TOKEN
    return str(info.value)


def test_each_alias_accepts_only_its_own_tokens_and_reveals_nothing_else() -> None:
    connection = SpyConnection()
    service = _service(connection)
    failures: set[str] = set()

    for target, source in itertools.permutations(ENGINES, 2):
        same_key_other_alias = TokenCodec(source, KEYS[target]).encrypt("a@example.com")
        other_alias_own_key = TokenCodec(source, KEYS[source]).encrypt("a@example.com")
        for token in (same_key_other_alias, other_alias_own_key, "pii:v1:AAAA", "pii:v1:"):
            failures.add(_run(service, target, token))

    assert len(failures) == 1, failures
    assert connection.calls == []


@pytest.mark.parametrize("alias", list(ENGINES))
def test_own_token_reaches_the_driver_as_a_bind_on_every_engine(alias: str) -> None:
    connection = SpyConnection(SpyResult(["Id"], [(1,)]))
    service = _service(connection)
    token = TokenCodec(alias, KEYS[alias]).encrypt("a@example.com")

    asyncio.run(service.execute_sql(alias, "app", QUERY.format(token=token)))

    ((statement, parameters),) = connection.calls
    assert parameters == ("a@example.com",)
    assert "a@example.com" not in statement
    assert token not in statement
    marker = "?" if ENGINES[alias] == "sqlserver" else "%s"
    assert statement.count(marker) == 1
