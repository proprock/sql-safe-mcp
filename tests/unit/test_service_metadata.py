"""Metadata operations through a registry that really runs the operation.

The registry records the alias and database it is asked for and calls the operation with a fake
engine; ``extras_for`` and ``reflect_tables`` are replaced by fakes that record their arguments.
The service clock advances one second per reading, so every ``elapsed_ms`` is exact.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import re
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest
import sqlalchemy as sa
from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError

from sql_safe_mcp import service as service_module
from sql_safe_mcp.config import AppConfig, RuntimeConfig, ServerConfig
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.models import StoredProcedureDefinition, StoredProcedureSummary, TableSummary
from sql_safe_mcp.service import DatabaseService

CONNECTION = object()
SERVICE_LOGGER = "sql_safe_mcp.service"
REFERENCE = r"[0-9a-f]{32}"


class _Connect:
    def __enter__(self) -> object:
        return CONNECTION

    def __exit__(self, *exc: object) -> None:
        return None


class _Engine:
    def connect(self) -> _Connect:
        return _Connect()


class RunningRegistry:
    def __init__(self, failure: BaseException | None = None) -> None:
        self.runs: list[tuple[str, str | None]] = []
        self.failure = failure

    async def run(self, alias: str, database: str | None, operation: Callable[[Any], Any]) -> Any:
        self.runs.append((alias, database))
        if self.failure is not None:
            raise self.failure
        return operation(_Engine())


class FakeExtras:
    def __init__(self) -> None:
        self.databases: list[str] = []
        self.procedures: list[StoredProcedureSummary] = []
        self.definition: StoredProcedureDefinition | None = None
        self.calls: list[tuple[object, ...]] = []

    def list_databases(self, connection: object) -> list[str]:
        self.calls.append(("list_databases", connection))
        return list(self.databases)

    def list_stored_procedures(
        self, connection: object, database: str
    ) -> list[StoredProcedureSummary]:
        self.calls.append(("list_stored_procedures", connection, database))
        return list(self.procedures)

    def get_stored_procedure(
        self, connection: object, database: str, schema: str | None, name: str
    ) -> StoredProcedureDefinition | None:
        self.calls.append(("get_stored_procedure", connection, database, schema, name))
        return self.definition


class World(SimpleNamespace):
    service: DatabaseService
    registry: RunningRegistry
    extras: FakeExtras
    engines: list[str]
    tables: list[TableSummary]
    reflected: list[object]


def _config() -> AppConfig:
    def server(access_level: Literal["metadata", "meta_and_code"]) -> ServerConfig:
        return ServerConfig(
            engine="sqlserver",
            access_level=access_level,
            connection_url=SecretStr("mssql+pyodbc://u:p@host/master?driver=x"),
        )

    return AppConfig(
        version=1,
        runtime=RuntimeConfig(max_definition_chars=1024),
        servers={"Beta": server("metadata"), "alpha": server("meta_and_code")},
    )


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    clock = itertools.count(10.0, 1.0)
    monkeypatch.setattr(service_module, "time", SimpleNamespace(perf_counter=lambda: next(clock)))
    state = World(extras=FakeExtras(), engines=[], tables=[], reflected=[])

    def extras_for(engine: str) -> FakeExtras:
        state.engines.append(engine)
        return state.extras

    def reflect_tables(connection: object) -> list[TableSummary]:
        state.reflected.append(connection)
        return list(state.tables)

    monkeypatch.setattr(service_module, "extras_for", extras_for)
    monkeypatch.setattr(service_module, "reflect_tables", reflect_tables)
    state.registry = RunningRegistry()
    state.service = DatabaseService(_config(), cast(EngineRegistry, state.registry))
    yield state


def _failing(world: World, failure: BaseException) -> None:
    world.registry = RunningRegistry(failure)
    world.service = DatabaseService(_config(), cast(EngineRegistry, world.registry))


def _ok_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == SERVICE_LOGGER and r.getMessage().startswith("operation ok")
    ]


def _error(awaitable: Any) -> DomainError:
    async def scenario() -> None:
        await awaitable

    with pytest.raises(DomainError) as raised:
        asyncio.run(scenario())
    return raised.value


def _proc(schema: str | None, name: str) -> StoredProcedureSummary:
    return StoredProcedureSummary(schema_=schema, name=name)


def _table(schema: str | None, name: str) -> TableSummary:
    return TableSummary(schema_=schema, name=name)


# --- servers and databases ---------------------------------------------------------------


def test_list_servers_sorts_aliases_ignoring_case(world: World) -> None:
    assert [item.name for item in world.service.list_servers().servers] == ["alpha", "Beta"]


def test_list_databases_runs_the_engine_operation_and_logs_it(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.extras.databases = ["Zed", "apple", "Mango"]

    with caplog.at_level(logging.INFO, logger=SERVICE_LOGGER):
        result = asyncio.run(world.service.list_databases("alpha"))

    assert [item.name for item in result.databases] == ["apple", "Mango", "Zed"]
    assert world.registry.runs == [("alpha", None)]
    assert world.engines == ["sqlserver"]
    assert world.extras.calls == [("list_databases", CONNECTION)]
    assert _ok_lines(caplog) == [
        "operation ok server=alpha database=- operation=list_databases elapsed_ms=1000"
    ]


# --- tables --------------------------------------------------------------------------------


def test_list_tables_runs_the_reflection_and_logs_it(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.tables = [_table("dbo", "b")]

    with caplog.at_level(logging.INFO, logger=SERVICE_LOGGER):
        asyncio.run(world.service.list_tables("alpha", "app"))

    assert world.registry.runs == [("alpha", "app")]
    assert world.reflected == [CONNECTION]
    assert _ok_lines(caplog) == [
        "operation ok server=alpha database=app operation=list_tables elapsed_ms=1000"
    ]


def test_list_tables_sorts_by_schema_then_name_ignoring_case(world: World) -> None:
    world.tables = [
        _table("dbo", "b"),
        _table(None, "z"),
        _table("Audit", "c"),
        _table("audit", "A"),
    ]

    result = asyncio.run(world.service.list_tables("alpha", "app"))

    assert [(t.schema_, t.name) for t in result.tables] == [
        (None, "z"),
        ("audit", "A"),
        ("Audit", "c"),
        ("dbo", "b"),
    ]


def test_list_tables_filters_on_schema_and_name(world: World) -> None:
    world.tables = [_table("dbo", "Users"), _table("dbo", "Orders"), _table(None, "Loose")]

    def names(schema: str | None, contains: str | None) -> list[str]:
        result = asyncio.run(world.service.list_tables("alpha", "app", schema, contains))
        return [t.name for t in result.tables]

    assert names("DBO", "USER") == ["Users"]
    assert names(None, "o") == ["Loose", "Orders"]
    assert names("", None) == ["Loose"]


def test_resolve_table_matches_an_empty_schema_to_a_schemaless_table() -> None:
    selected = DatabaseService._resolve_table([_table(None, "T")], "t", "")

    assert selected.name == "T"


def test_resolve_table_errors_name_the_table_and_the_qualified_candidates() -> None:
    with pytest.raises(DomainError) as missing:
        DatabaseService._resolve_table([], "missing", None)
    with pytest.raises(DomainError) as ambiguous:
        DatabaseService._resolve_table(
            [_table("dbo", "Users"), _table("audit", "Users")], "users", None
        )

    assert (missing.value.code, missing.value.public_message, missing.value.hint) == (
        ErrorCode.NOT_FOUND,
        "Table 'missing' was not found.",
        None,
    )
    assert (ambiguous.value.code, ambiguous.value.public_message, ambiguous.value.hint) == (
        ErrorCode.AMBIGUOUS_OBJECT,
        "Table 'users' is ambiguous.",
        "Specify schema; candidates: dbo.Users, audit.Users.",
    )


# --- stored procedures ---------------------------------------------------------------------


def test_list_stored_procedures_runs_the_engine_operation_and_logs_it(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.extras.procedures = [_proc("dbo", "Refresh")]

    with caplog.at_level(logging.INFO, logger=SERVICE_LOGGER):
        asyncio.run(world.service.list_stored_procedures("alpha", "app"))

    assert world.registry.runs == [("alpha", "app")]
    assert world.extras.calls == [("list_stored_procedures", CONNECTION, "app")]
    assert _ok_lines(caplog) == [
        "operation ok server=alpha database=app operation=list_stored_procedures elapsed_ms=1000"
    ]


def test_list_stored_procedures_sorts_and_filters(world: World) -> None:
    world.extras.procedures = [
        _proc("dbo", "b"),
        _proc(None, "z"),
        _proc("Audit", "c"),
        _proc("audit", "A"),
        _proc("dbo", "Refresh"),
    ]

    def listed(
        schema: str | None = None, contains: str | None = None
    ) -> list[tuple[str | None, str]]:
        result = asyncio.run(world.service.list_stored_procedures("alpha", "app", schema, contains))
        return [(p.schema_, p.name) for p in result.stored_procedures]

    assert listed() == [
        (None, "z"),
        ("audit", "A"),
        ("Audit", "c"),
        ("dbo", "b"),
        ("dbo", "Refresh"),
    ]
    assert listed("dbo", "fresh") == [("dbo", "Refresh")]
    assert listed(None, "Z") == [(None, "z")]
    assert listed("", None) == [(None, "z")]


def test_get_stored_procedure_reads_the_selected_procedure(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    world.extras.procedures = [_proc("dbo", "Refresh"), _proc("audit", "Refresh")]
    definition = StoredProcedureDefinition(
        schema_="dbo", name="Refresh", definition="x" * 1024, definition_available=True
    )
    world.extras.definition = definition

    with caplog.at_level(logging.INFO, logger=SERVICE_LOGGER):
        result = asyncio.run(world.service.get_stored_procedure("alpha", "app", "refresh", "DBO"))

    assert result is definition
    assert world.registry.runs == [("alpha", "app"), ("alpha", "app")]
    assert world.engines == ["sqlserver", "sqlserver"]
    assert world.extras.calls == [
        ("list_stored_procedures", CONNECTION, "app"),
        ("get_stored_procedure", CONNECTION, "app", "dbo", "Refresh"),
    ]
    assert _ok_lines(caplog)[-1] == (
        "operation ok server=alpha database=app operation=get_stored_procedure elapsed_ms=1000"
    )


def test_get_stored_procedure_ambiguity_names_the_qualified_candidates(world: World) -> None:
    world.extras.procedures = [_proc("dbo", "Refresh"), _proc("audit", "Refresh")]

    error = _error(world.service.get_stored_procedure("alpha", "app", "refresh"))

    assert (error.code, error.public_message, error.hint) == (
        ErrorCode.AMBIGUOUS_OBJECT,
        "Stored procedure 'refresh' is ambiguous.",
        "Specify schema; candidates: audit.Refresh, dbo.Refresh.",
    )


def test_get_stored_procedure_rejects_only_a_definition_over_the_limit(world: World) -> None:
    world.extras.procedures = [_proc("dbo", "Large")]
    world.extras.definition = StoredProcedureDefinition(
        schema_="dbo", name="Large", definition="x" * 1025, definition_available=True
    )

    error = _error(world.service.get_stored_procedure("alpha", "app", "large"))
    world.extras.definition = world.extras.definition.model_copy(update={"definition": "x" * 1024})
    at_limit = asyncio.run(world.service.get_stored_procedure("alpha", "app", "large"))

    assert (error.code, error.public_message, error.hint) == (
        ErrorCode.DEFINITION_TOO_LARGE,
        "Stored procedure definition exceeds the configured response limit.",
        None,
    )
    assert at_limit.definition == "x" * 1024


# --- public errors -------------------------------------------------------------------------


def test_unknown_server_error_names_the_alias_and_the_discovery_tool(world: World) -> None:
    error = _error(world.service.list_databases("nope"))

    assert (error.code, error.public_message, error.hint) == (
        ErrorCode.UNKNOWN_SERVER,
        "Unknown configured server 'nope'.",
        "Call list_servers to discover configured aliases.",
    )


def test_stored_procedure_tools_name_the_required_access_levels(world: World) -> None:
    error = _error(world.service.list_stored_procedures("Beta", "app"))

    assert (error.code, error.public_message, error.hint) == (
        ErrorCode.ACCESS_LEVEL_DENIED,
        "Stored procedure tools are available only for meta_and_code or all_pii_safe servers.",
        "Use a server configured with access_level meta_and_code or all_pii_safe.",
    )


# --- failure log lines ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("failure", "message", "error_class"),
    [
        (RuntimeError("secret"), "Unexpected database operation failure", "RuntimeError"),
        (
            DBAPIError("SELECT 1", None, Exception("no known signal")),
            "Database operation failed",
            "DBAPIError",
        ),
    ],
    ids=["unexpected", "unclassified-dbapi"],
)
@pytest.mark.parametrize(
    ("call", "database"),
    [
        (lambda s: s.list_databases("alpha"), "-"),
        (lambda s: s.list_tables("alpha", "app"), "app"),
    ],
    ids=["no-database", "database"],
)
def test_unclassified_failure_log_line_is_fixed(
    world: World,
    caplog: pytest.LogCaptureFixture,
    failure: BaseException,
    message: str,
    error_class: str,
    call: Callable[[DatabaseService], Any],
    database: str,
) -> None:
    _failing(world, failure)

    with caplog.at_level(logging.INFO, logger=SERVICE_LOGGER):
        error = _error(call(world.service))

    operation = "list_databases" if database == "-" else "list_tables"
    (line,) = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert line == (
        f"{message}; server=alpha database={database} operation={operation} "
        f"error_class={error_class} reference={error.correlation_id}"
    )
    assert re.fullmatch(REFERENCE, error.correlation_id or "")


def test_timeout_log_line_keeps_the_database(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    _failing(world, DBAPIError("SELECT 1", None, Exception("HYT00", "x")))

    with caplog.at_level(logging.INFO, logger=SERVICE_LOGGER):
        error = _error(world.service.list_tables("alpha", "app"))

    assert error.code is ErrorCode.TIMEOUT
    assert "operation failed server=alpha database=app operation=list_tables code=TIMEOUT" in (
        caplog.text
    )


# --- schema cache --------------------------------------------------------------------------


def test_reflected_catalog_reads_through_the_service_schema_cache() -> None:
    service = DatabaseService(_config(), cast(EngineRegistry, RunningRegistry()))
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE Users (Id INTEGER, Email TEXT)"))
        catalog = service._reflected_catalog(connection, "alpha", "main")

        first = catalog.list_tables()
        connection.execute(sa.text("CREATE TABLE Later (Id INTEGER)"))
        second = catalog.list_tables()
        columns = [column.name for column in catalog.columns("main", "Users")]
    engine.dispose()

    assert first == second == [("main", "Users")]
    assert columns == ["Id", "Email"]
