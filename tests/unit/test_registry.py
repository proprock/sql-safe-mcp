from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from typing import Any, Literal
from unittest.mock import Mock

import pymysql.err
import pytest
from pydantic import SecretStr

from sql_safe_mcp.config import AppConfig, RuntimeConfig, ServerConfig
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.errors import DomainError, ErrorCode

HOSTILE_DATABASE = "x\naudit server=s database=app row_count=0\r"


def _assert_one_safe_line_each(caplog: pytest.LogCaptureFixture) -> None:
    assert caplog.records
    for record in caplog.records:
        message = record.getMessage()
        assert "\n" not in message
        assert "\r" not in message
        assert not message.startswith("audit ")
    assert "database=x?audit?server?s?database?app?row_count?0?" in caplog.text


def test_connect_log_lines_sanitize_the_database(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock())
    listeners: dict[str, Callable[..., Any]] = {}

    def listens_for(_target: object, name: str) -> Callable[[Callable[..., Any]], Any]:
        def register(function: Callable[..., Any]) -> Callable[..., Any]:
            listeners[name] = function
            return function

        return register

    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", listens_for)
    EngineRegistry(_config()).get("one", HOSTILE_DATABASE)
    dialect = Mock()
    caplog.set_level(logging.INFO, logger="sql_safe_mcp")

    listeners["do_connect"](dialect, Mock(), ("dsn",), {})
    dialect.connect.side_effect = _ConnectFailure("28000", "[28000] Login failed")
    with pytest.raises(_ConnectFailure):
        listeners["do_connect"](dialect, Mock(), ("dsn",), {})

    assert [r.getMessage().split(" server=")[0] for r in caplog.records] == [
        "connect ok",
        "connect failed",
    ]
    _assert_one_safe_line_each(caplog)


def test_engine_creation_and_eviction_log_lines_sanitize_the_database(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock())
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", lambda *_args: lambda fn: fn)
    registry = EngineRegistry(_config(cache_size=1))
    caplog.set_level(logging.DEBUG, logger="sql_safe_mcp")

    registry.get("one", HOSTILE_DATABASE)
    registry.get("one", "other")

    messages = [r.getMessage() for r in caplog.records]
    assert [m.split(" server=")[0] for m in messages] == [
        "engine created",
        "engine created",
        "engine evicted",
    ]
    for message in messages[:1] + messages[2:]:
        assert "\n" not in message and "\r" not in message
        assert "database=x?audit?server?s?database?app?row_count?0?" in message


def _config(cache_size: int = 1, concurrency: int = 8) -> AppConfig:
    return AppConfig(
        version=1,
        runtime=RuntimeConfig(
            engine_cache_size=cache_size,
            max_concurrent_db_operations=concurrency,
        ),
        servers={
            "one": ServerConfig(
                engine="sqlserver",
                connection_url=SecretStr("mssql+pyodbc://u:p@sql-host/master?driver=x"),
            )
        },
    )


def test_registry_is_lazy_and_disposes_evicted_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    created = [Mock(), Mock()]
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock(side_effect=created))
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", lambda *_args: lambda fn: fn)
    registry = EngineRegistry(_config())

    assert registry.cached_engine_count == 0
    assert registry.get("one", "db1") is created[0]
    assert registry.get("one", "db2") is created[1]

    created[0].dispose.assert_called_once_with()
    assert registry.cached_engine_count == 1


def test_registry_reuses_same_alias_and_database(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = Mock()
    create = Mock(return_value=engine)
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", create)
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", lambda *_args: lambda fn: fn)
    registry = EngineRegistry(_config())

    assert registry.get("one", "db") is registry.get("one", "db")
    create.assert_called_once()


def test_registry_dispose_closes_all_cached_engines(monkeypatch: pytest.MonkeyPatch) -> None:
    engines = [Mock(), Mock()]
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock(side_effect=engines))
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", lambda *_args: lambda fn: fn)
    registry = EngineRegistry(_config(cache_size=2))
    registry.get("one", "db1")
    registry.get("one", "db2")

    registry.dispose()

    assert registry.cached_engine_count == 0
    for engine in engines:
        engine.dispose.assert_called_once_with()


def test_registry_limits_concurrent_database_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = Mock()
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock(return_value=engine))
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", lambda *_args: lambda fn: fn)
    registry = EngineRegistry(_config(concurrency=2))
    lock = threading.Lock()
    active = 0
    peak = 0

    def operation(_engine: object) -> None:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.03)
        with lock:
            active -= 1

    async def scenario() -> None:
        await asyncio.gather(*(registry.run("one", "db", operation) for _ in range(6)))

    asyncio.run(scenario())

    assert peak == 2


def test_registry_rejects_unknown_alias_before_engine_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create = Mock()
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", create)
    registry = EngineRegistry(_config())

    with pytest.raises(DomainError) as raised:
        registry.get("missing", "db")

    assert raised.value.code is ErrorCode.UNKNOWN_SERVER
    create.assert_not_called()


def test_registry_configures_pool_database_and_cursor_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = Mock()
    create = Mock(return_value=engine)
    callbacks: dict[str, Callable[..., None]] = {}

    def listens_for(_engine: object, event_name: str) -> Callable[..., object]:
        def decorate(callback: Callable[..., None]) -> Callable[..., None]:
            callbacks[event_name] = callback
            return callback

        return decorate

    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", create)
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", listens_for)
    registry = EngineRegistry(_config())

    assert registry.get("one", "tenant") is engine

    url = create.call_args.args[0]
    assert url.database == "tenant"
    assert create.call_args.kwargs == {
        "pool_size": 2,
        "max_overflow": 2,
        "pool_timeout": 10,
        "pool_pre_ping": True,
        "pool_use_lifo": True,
    }
    connect_callback = callbacks["connect"]
    dbapi_connection = Mock(timeout=0)
    connect_callback(dbapi_connection, None)
    assert dbapi_connection.timeout == 30

    connect_callback(object(), None)

    callback = callbacks["before_cursor_execute"]
    cursor = Mock(timeout=0)
    callback(None, cursor, "SELECT secret", {"password": "hidden"}, None, False)
    assert cursor.timeout == 30

    callback(None, object(), "SELECT 1", {}, None, False)


@pytest.mark.parametrize("engine", ["mysql", "mariadb"])
def test_registry_passes_pymysql_timeouts_as_connect_args(
    monkeypatch: pytest.MonkeyPatch, engine: Literal["mysql", "mariadb"]
) -> None:
    create = Mock(return_value=Mock())
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", create)
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", lambda *_args: lambda fn: fn)
    config = AppConfig(
        version=1,
        servers={
            "one": ServerConfig(
                engine=engine,
                connection_url=SecretStr("mysql+pymysql://u:p@one/app"),
            )
        },
    )

    EngineRegistry(config).get("one", "tenant")

    # The client gives up 5 s after the server limit, so the server aborts the query first.
    assert create.call_args.kwargs["connect_args"] == {
        "connect_timeout": 10,
        "read_timeout": 35,
        "write_timeout": 30,
    }


def _connect_callbacks(
    monkeypatch: pytest.MonkeyPatch, engine: Literal["mysql", "mariadb", "sqlserver"]
) -> list[Callable[..., None]]:
    callbacks: list[Callable[..., None]] = []

    def listens_for(_engine: object, event_name: str) -> Callable[..., object]:
        def decorate(callback: Callable[..., None]) -> Callable[..., None]:
            if event_name == "connect":
                callbacks.append(callback)
            return callback

        return decorate

    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock(return_value=Mock()))
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", listens_for)
    url = "mysql+pymysql://u:p@one/app" if engine != "sqlserver" else "mssql+pyodbc://u:p@one/app"
    config = AppConfig(
        version=1,
        servers={"one": ServerConfig(engine=engine, connection_url=SecretStr(url))},
        runtime=RuntimeConfig(statement_timeout_seconds=7),
    )
    EngineRegistry(config).get("one", "tenant")
    return callbacks


@pytest.mark.parametrize(
    ("engine", "variable", "value"),
    [("mysql", "max_execution_time", 7000), ("mariadb", "max_statement_time", 7)],
)
def test_mysql_sessions_get_a_server_side_statement_limit_in_the_engine_unit(
    monkeypatch: pytest.MonkeyPatch,
    engine: Literal["mysql", "mariadb"],
    variable: str,
    value: int,
) -> None:
    cursor = Mock()
    cursor.fetchone.return_value = ("STRICT_TRANS_TABLES",)
    connection = Mock()
    connection.cursor.return_value = cursor

    for callback in _connect_callbacks(monkeypatch, engine):
        callback(connection, None)

    cursor.execute.assert_any_call(f"SET SESSION {variable} = %s", (value,))


def test_sqlserver_sessions_set_no_server_side_statement_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = Mock(timeout=0)

    for callback in _connect_callbacks(monkeypatch, "sqlserver"):
        callback(connection, None)

    connection.cursor.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [pymysql.err.MySQLError(), pymysql.err.OperationalError(1064, "syntax")],
    ids=["no-args", "other-code"],
)
def test_other_driver_errors_on_the_limit_statement_propagate_unchanged(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    cursor = Mock()
    cursor.fetchone.return_value = ("STRICT_TRANS_TABLES",)

    def execute(sql: str, *_: object) -> None:
        if "_time" in sql:
            raise failure

    cursor.execute.side_effect = execute
    connection = Mock()
    connection.cursor.return_value = cursor

    with pytest.raises(pymysql.err.MySQLError) as raised:
        for callback in _connect_callbacks(monkeypatch, "mysql"):
            callback(connection, None)

    assert raised.value is failure
    cursor.close.assert_called()


@pytest.mark.parametrize(
    ("engine", "other"), [("mysql", "mariadb"), ("mariadb", "mysql")], ids=["mysql", "mariadb"]
)
def test_the_wrong_engine_setting_names_the_fix(
    monkeypatch: pytest.MonkeyPatch,
    engine: Literal["mysql", "mariadb"],
    other: str,
) -> None:
    cursor = Mock()
    cursor.fetchone.return_value = ("STRICT_TRANS_TABLES",)

    def execute(sql: str, *_: object) -> None:
        if "_time" in sql:
            raise pymysql.err.OperationalError(1193, "Unknown system variable 'secret-looking'")

    cursor.execute.side_effect = execute
    connection = Mock()
    connection.cursor.return_value = cursor

    with pytest.raises(DomainError) as raised:
        for callback in _connect_callbacks(monkeypatch, engine):
            callback(connection, None)

    assert raised.value.code is ErrorCode.CONFIG_ERROR
    assert f"engine: {other}" in str(raised.value)
    assert f"engine: {engine}" in str(raised.value)
    assert "secret-looking" not in str(raised.value)
    cursor.close.assert_called()


def test_a_server_without_the_statement_limit_variable_fails_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = Mock()
    cursor.fetchone.return_value = ("STRICT_TRANS_TABLES",)
    cursor.execute.side_effect = lambda sql, *_: (
        (_ for _ in ()).throw(RuntimeError("Unknown system variable"))
        if "max_execution_time" in sql
        else None
    )
    connection = Mock()
    connection.cursor.return_value = cursor

    with pytest.raises(RuntimeError, match="Unknown system variable"):
        for callback in _connect_callbacks(monkeypatch, "mysql"):
            callback(connection, None)

    cursor.close.assert_called()


def test_registry_removes_no_backslash_escapes_from_mysql_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callbacks: list[Callable[..., None]] = []

    def listens_for(_engine: object, event_name: str) -> Callable[..., object]:
        def decorate(callback: Callable[..., None]) -> Callable[..., None]:
            if event_name == "connect":
                callbacks.append(callback)
            return callback

        return decorate

    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock(return_value=Mock()))
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", listens_for)
    config = AppConfig(
        version=1,
        servers={
            "one": ServerConfig(
                engine="mysql", connection_url=SecretStr("mysql+pymysql://u:p@one/app")
            )
        },
    )

    EngineRegistry(config).get("one", "tenant")

    cursor = Mock()
    cursor.fetchone.return_value = ("ANSI_QUOTES,NO_BACKSLASH_ESCAPES,STRICT_TRANS_TABLES",)
    connection = Mock()
    connection.cursor.return_value = cursor
    for callback in callbacks:
        callback(connection, None)

    cursor.execute.assert_any_call(
        "SET SESSION sql_mode = %s", ("ANSI_QUOTES,STRICT_TRANS_TABLES",)
    )
    # One cursor for this listener and one for the server statement limit listener.
    assert cursor.close.call_count == 2


class _ConnectFailure(Exception):
    """Shaped like pyodbc.Error: args are (sqlstate, message)."""


def _registry_with_listeners(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[EngineRegistry, dict[str, Callable[..., object]]]:
    listeners: dict[str, Callable[..., object]] = {}

    def listens_for(
        _target: object, name: str
    ) -> Callable[[Callable[..., object]], Callable[..., object]]:
        def register(fn: Callable[..., object]) -> Callable[..., object]:
            listeners.setdefault(name, fn)
            return fn

        return register

    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock())
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", listens_for)
    registry = EngineRegistry(_config())
    registry.get("one", "db1")
    return registry, listeners


def test_successful_connect_is_logged_with_alias_database_and_elapsed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _, listeners = _registry_with_listeners(monkeypatch)
    dialect = Mock()
    dialect.connect.return_value = "dbapi-connection"
    caplog.set_level(logging.INFO, logger="sql_safe_mcp")

    result = listeners["do_connect"](dialect, Mock(), ("dsn",), {"timeout": 5})

    assert result == "dbapi-connection"
    dialect.connect.assert_called_once_with("dsn", timeout=5)
    assert "connect ok server=one database=db1 elapsed_ms=" in caplog.text


def test_failed_connect_is_logged_without_secrets_and_reraised(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _, listeners = _registry_with_listeners(monkeypatch)
    dialect = Mock()
    failure = _ConnectFailure("28000", "[28000] Login failed for user 'u' (pwd p) on sql-host")
    dialect.connect.side_effect = failure
    caplog.set_level(logging.INFO, logger="sql_safe_mcp")

    with pytest.raises(_ConnectFailure):
        listeners["do_connect"](dialect, Mock(), ("dsn",), {})

    assert "connect failed server=one database=db1 elapsed_ms=" in caplog.text
    assert "sqlstate=28000" in caplog.text
    assert "Login failed for user" in caplog.text
    for leaked in ("'u'", "pwd p", "sql-host"):
        assert leaked not in caplog.text
    assert "on one" in caplog.text
    assert "mssql+pyodbc" not in caplog.text


def test_engine_creation_and_eviction_are_logged_at_debug(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("sql_safe_mcp.db.registry.create_engine", Mock())
    monkeypatch.setattr("sql_safe_mcp.db.registry.event.listens_for", lambda *_args: lambda fn: fn)
    registry = EngineRegistry(_config(cache_size=1))
    caplog.set_level(logging.DEBUG, logger="sql_safe_mcp")

    registry.get("one", "db1")
    registry.get("one", "db2")

    assert "engine created server=one engine=sqlserver database=db1" in caplog.text
    assert "engine evicted server=one database=db1" in caplog.text
    assert "mssql+pyodbc" not in caplog.text
