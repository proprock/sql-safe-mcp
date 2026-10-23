from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import Callable, Sequence
from typing import Any, ClassVar, cast

import pytest
from sqlalchemy.exc import DataError, DBAPIError, OperationalError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from typed_columns import typed

from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.schema import ColumnSchema
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.service import DatabaseService

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
CODEC = TokenCodec("secure", KEY)


class FakeResult:
    def __init__(self, keys: Sequence[str], rows: Sequence[tuple[Any, ...]]) -> None:
        self._keys = list(keys)
        self._rows = list(rows)
        self.fetch_sizes: list[int] = []

    def keys(self) -> list[str]:
        return self._keys

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        self.fetch_sizes.append(size)
        return self._rows[:size]

    def close(self) -> None:
        pass


class FakeConnection:
    def __init__(self, result: FakeResult, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def exec_driver_sql(self, statement: str, parameters: tuple[Any, ...]) -> FakeResult:
        self.calls.append((statement, parameters))
        if self.error is not None:
            raise self.error
        return self.result

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class FakeEngine:
    def __init__(self, connection: FakeConnection) -> None:
        self._connection = connection

    def connect(self) -> FakeConnection:
        return self._connection


class FakeRegistry:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.runs: list[tuple[str, str | None]] = []

    async def run(self, alias: str, database: str | None, operation: Callable[[Any], Any]) -> Any:
        self.runs.append((alias, database))
        return operation(FakeEngine(self.connection))


class FakeCatalog:
    tables: ClassVar[dict[tuple[str, str], list[str]]] = {
        ("dbo", "Users"): ["Id", "Email", "Name"],
    }

    def list_tables(self) -> list[tuple[str, str]]:
        return list(self.tables)

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        return typed(self.tables[(schema, table)])


def _config() -> AppConfig:
    url = "mssql+pyodbc://user:p%40ss@sql/master?driver=x"
    return AppConfig.model_validate(
        {
            "version": 1,
            "runtime": {"default_max_rows": 3, "hard_max_rows": 5},
            "servers": {
                "plain": {"engine": "sqlserver", "connection_url": url},
                "code": {
                    "engine": "sqlserver",
                    "access_level": "meta_and_code",
                    "connection_url": url,
                },
                "secure": {
                    "engine": "sqlserver",
                    "access_level": "all_pii_safe",
                    "connection_url": url,
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
                "other": {
                    "engine": "sqlserver",
                    "access_level": "all_pii_safe",
                    "connection_url": url,
                    "pii_key_env": "K2",
                    "pii_key": base64.b64encode(OTHER_KEY).decode(),
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
            },
        }
    )


def make(
    rows: Sequence[tuple[Any, ...]] = (),
    keys: Sequence[str] = ("Id",),
    error: Exception | None = None,
) -> tuple[DatabaseService, FakeRegistry]:
    registry = FakeRegistry(FakeConnection(FakeResult(keys, rows), error))
    service = DatabaseService(
        _config(),
        cast(EngineRegistry, registry),
        catalog_factory=lambda connection, alias, database: FakeCatalog(),
    )
    return service, registry


def execute(service: DatabaseService, sql: str, server: str = "secure", **kwargs: Any):
    return asyncio.run(service.execute_sql(server, "app", sql, **kwargs))


def error_of(
    service: DatabaseService, sql: str, server: str = "secure", **kwargs: Any
) -> DomainError:
    with pytest.raises(DomainError) as info:
        execute(service, sql, server, **kwargs)
    return info.value


def test_metadata_alias_is_denied_without_touching_the_database() -> None:
    service, registry = make()
    for alias in ("plain", "code"):
        error = error_of(service, "SELECT Id FROM Users", alias)
        assert error.code is ErrorCode.ACCESS_LEVEL_DENIED
    assert registry.runs == []


def test_unknown_server() -> None:
    service, _ = make()
    assert error_of(service, "SELECT 1", "nope").code is ErrorCode.UNKNOWN_SERVER


def test_valid_projection_returns_structured_result() -> None:
    service, registry = make(rows=[(1, "a@b.c", "n"), (2, None, "m")], keys=["Id", "Email", "Name"])
    result = execute(service, "SELECT Id, Email AS Contact, Name FROM Users")
    assert [(c.name, c.protected, c.encoding) for c in result.columns] == [
        ("Id", False, "json"),
        ("Contact", True, "token"),
        ("Name", False, "json"),
    ]
    assert result.columns[1].source is not None
    assert (result.columns[1].source.schema_, result.columns[1].source.table) == ("dbo", "Users")
    assert result.columns[1].source.column == "Email"
    assert result.row_count == 2
    assert result.truncated is False
    assert CODEC.decrypt(result.rows[0][1]) == "a@b.c"
    assert result.rows[1][1] is None
    assert "a@b.c" not in repr(result.model_dump())
    assert registry.runs == [("secure", "app")]


def test_token_predicate_is_bound_not_interpolated() -> None:
    service, registry = make(rows=[(1,)])
    token = CODEC.encrypt("x'; DROP TABLE Canary;--")
    execute(service, f"SELECT Id FROM Users WHERE Email = '{token}'")
    statement, parameters = registry.connection.calls[0]
    assert parameters == ("x'; DROP TABLE Canary;--",)
    assert "DROP" not in statement
    assert "pii:v1" not in statement


def test_rejected_query_never_reaches_the_sink() -> None:
    service, registry = make()
    for sql in [
        "DELETE FROM Users",
        "SELECT Id FROM Users; SELECT 1",
        "SELECT Id FROM Users WHERE Email = 'plain'",
        "SELECT Id FROM Users ORDER BY Email",
        "SELECT Id FROM Missing",
    ]:
        assert error_of(service, sql).code is ErrorCode.QUERY_REJECTED
    assert registry.connection.calls == []


def test_token_of_another_alias_is_invalid() -> None:
    service, registry = make()
    token = TokenCodec("other", OTHER_KEY).encrypt("a")
    error = error_of(service, f"SELECT Id FROM Users WHERE Email = '{token}'")
    assert error.code is ErrorCode.INVALID_PII_TOKEN
    assert registry.connection.calls == []


def test_default_and_explicit_row_limits() -> None:
    service, registry = make(rows=[(i,) for i in range(20)])
    result = execute(service, "SELECT Id FROM Users")
    assert result.row_count == 3
    assert result.truncated is True
    assert registry.connection.result.fetch_sizes == [4]
    result = execute(service, "SELECT Id FROM Users", max_rows=5)
    assert (result.row_count, result.truncated) == (5, True)
    assert registry.connection.result.fetch_sizes == [4, 6]


def test_invalid_row_limits() -> None:
    service, registry = make()
    assert error_of(service, "SELECT Id FROM Users", max_rows=0).code is ErrorCode.INVALID_ARGUMENT
    assert (
        error_of(service, "SELECT Id FROM Users", max_rows=6).code
        is ErrorCode.RESULT_LIMIT_EXCEEDED
    )
    assert registry.connection.calls == []


def test_database_errors_are_redacted_and_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    secret = "SELECT secret_column FROM hidden WHERE token = 'pii:v1:leak'"
    driver = DBAPIError(secret, ("bind-value-leak",), Exception("driver says: secret_column"))
    service, _ = make(error=driver)
    with caplog.at_level(logging.DEBUG):
        error = error_of(service, "SELECT Id FROM Users")
    text = str(error) + caplog.text
    assert error.code is ErrorCode.DATABASE_ERROR
    assert error.correlation_id
    for leaked in ("secret_column", "bind-value-leak", "pii:v1:leak", "hidden"):
        assert leaked not in text


CANARY = "canary.person@example.org"


@pytest.mark.parametrize(
    "driver",
    [
        DBAPIError("stmt", (), Exception(f"[HYT00] Query timeout expired near '{CANARY}'")),
        DBAPIError("stmt", (), Exception(f"[08001] Cannot open database near '{CANARY}'")),
        DBAPIError("stmt", (), Exception(f"Permission was denied on '{CANARY}'")),
        DBAPIError("stmt", (), Exception(f"Conversion failed when converting '{CANARY}' to int")),
        OperationalError("stmt", (), Exception(f"lost connection near '{CANARY}'")),
        DataError("stmt", (), Exception(f"Data truncated for value N'{CANARY}'")),
        SQLAlchemyTimeoutError(f"QueuePool limit reached near '{CANARY}'"),
    ],
    ids=["timeout", "connection", "denied", "unclassified", "operational", "data", "pool-timeout"],
)
def test_execute_sql_failures_never_log_driver_message_text(
    driver: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    service, _ = make(error=driver)
    with caplog.at_level(logging.DEBUG):
        error = error_of(service, "SELECT Id FROM Users")
    assert CANARY not in caplog.text
    assert CANARY not in str(error)
    assert "message=" not in caplog.text


def test_other_operations_log_the_redacted_driver_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver = DBAPIError("stmt", (), Exception(f"[HYT00] Login timeout near '{CANARY}'"))
    service, _ = make(error=driver)
    with caplog.at_level(logging.DEBUG), pytest.raises(DomainError):
        asyncio.run(service._run("secure", "app", "list_tables", service_raises(driver)))
    assert CANARY not in caplog.text
    assert "Login timeout near '***'" in caplog.text


def service_raises(error: Exception) -> Callable[[Any], Any]:
    def operation(engine: Any) -> Any:
        raise error

    return operation


def test_statement_timeout_is_a_public_timeout() -> None:
    driver = DBAPIError("stmt", (), Exception("[HYT00] Query timeout expired"))
    service, _ = make(error=driver)
    error = error_of(service, "SELECT Id FROM Users")
    assert error.code is ErrorCode.TIMEOUT
    assert error.retryable is True


def test_permission_errors_are_access_denied() -> None:
    driver = DBAPIError("stmt", (), Exception("The SELECT permission was denied on the object"))
    service, _ = make(error=driver)
    assert error_of(service, "SELECT Id FROM Users").code is ErrorCode.ACCESS_DENIED


def test_unsupported_result_types_are_a_controlled_error() -> None:
    service, _ = make(rows=[(object(),)])
    assert error_of(service, "SELECT Id FROM Users").code is ErrorCode.DATABASE_ERROR
