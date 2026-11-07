from __future__ import annotations

import asyncio
import logging
from typing import Any, cast

import pytest
from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError, OperationalError, ProgrammingError
from sqlalchemy.exc import TimeoutError as SqlAlchemyTimeoutError

from sql_safe_mcp.config import AppConfig, RuntimeConfig, ServerConfig
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.models import (
    StoredProcedureDefinition,
    StoredProcedureSummary,
    TableSummary,
)
from sql_safe_mcp.service import DatabaseService


class StubRegistry:
    def __init__(self, *responses: object) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str | None]] = []

    async def run(self, alias: str, database: str | None, operation: object) -> Any:
        del operation
        self.calls.append((alias, database))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


def _service(*responses: object, max_definition_chars: int = 1024) -> DatabaseService:
    config = AppConfig(
        version=1,
        runtime=RuntimeConfig(max_definition_chars=max_definition_chars),
        servers={
            "zeta": ServerConfig(
                engine="sqlserver",
                access_level="meta_and_code",
                connection_url=SecretStr("mssql+pyodbc://u:p@zeta/master?driver=x"),
            ),
            "Alpha": ServerConfig(
                engine="sqlserver",
                access_level="meta_and_code",
                connection_url=SecretStr("mssql+pyodbc://u:p@alpha/master?driver=x"),
            ),
        },
    )
    return DatabaseService(config, cast(EngineRegistry, StubRegistry(*responses)))


def test_resolve_table_requires_schema_when_name_is_ambiguous() -> None:
    tables = [
        TableSummary(schema_="dbo", name="Users"),
        TableSummary(schema_="audit", name="Users"),
    ]

    with pytest.raises(DomainError, match="AMBIGUOUS_OBJECT"):
        DatabaseService._resolve_table(tables, "users", None)


def test_resolve_table_matches_case_insensitively() -> None:
    tables = [TableSummary(schema_="dbo", name="Users")]

    selected = DatabaseService._resolve_table(tables, "users", "DBO")

    assert selected.name == "Users"


def test_resolve_table_uses_explicit_schema_for_duplicate_names() -> None:
    tables = [
        TableSummary(schema_="dbo", name="Users"),
        TableSummary(schema_="audit", name="Users"),
    ]

    selected = DatabaseService._resolve_table(tables, "USERS", "Audit")

    assert selected.schema_ == "audit"


def test_resolve_table_returns_not_found_for_missing_name() -> None:
    with pytest.raises(DomainError, match="NOT_FOUND"):
        DatabaseService._resolve_table([], "missing", None)


def test_metadata_alias_cannot_list_stored_procedures_without_database_access() -> None:
    registry = StubRegistry()
    service = DatabaseService(
        AppConfig(
            version=1,
            servers={
                "tables": ServerConfig(
                    engine="sqlserver",
                    connection_url=SecretStr("mssql+pyodbc://u:p@tables/master?driver=x"),
                )
            },
        ),
        cast(EngineRegistry, registry),
    )

    async def scenario() -> None:
        for operation in (
            lambda: service.list_stored_procedures("tables", "app"),
            lambda: service.get_stored_procedure("tables", "app", "Refresh"),
        ):
            with pytest.raises(DomainError) as raised:
                await operation()
            assert raised.value.code is ErrorCode.ACCESS_LEVEL_DENIED

    asyncio.run(scenario())
    assert registry.calls == []


def test_list_servers_and_metadata_filters_are_case_insensitive() -> None:
    service = _service(
        ["master", "Warehouse", "Archive"],
        [
            TableSummary(schema_="dbo", name="Users"),
            TableSummary(schema_="audit", name="UserEvents"),
            TableSummary(schema_="dbo", name="Orders"),
        ],
        [
            StoredProcedureSummary(schema_="dbo", name="RefreshUsers"),
            StoredProcedureSummary(schema_="audit", name="WriteUserEvent"),
            StoredProcedureSummary(schema_="dbo", name="RefreshOrders"),
        ],
    )

    async def scenario() -> None:
        assert [item.name for item in service.list_servers().servers] == ["Alpha", "zeta"]
        databases = await service.list_databases("Alpha", "WARE")
        assert [item.name for item in databases.databases] == ["Warehouse"]
        tables = await service.list_tables("Alpha", "Application", "AUDIT", "user")
        assert [(item.schema_, item.name) for item in tables.tables] == [("audit", "UserEvents")]
        procedures = await service.list_stored_procedures("Alpha", "Application", "dbo", "refresh")
        assert [(item.schema_, item.name) for item in procedures.stored_procedures] == [
            ("dbo", "RefreshOrders"),
            ("dbo", "RefreshUsers"),
        ]

    asyncio.run(scenario())


def test_get_stored_procedure_handles_ambiguity_hidden_and_oversized_definition() -> None:
    ambiguous = _service(
        [
            StoredProcedureSummary(schema_="dbo", name="Refresh"),
            StoredProcedureSummary(schema_="audit", name="Refresh"),
        ]
    )
    hidden = StoredProcedureDefinition(
        schema_="dbo", name="Hidden", definition=None, definition_available=False
    )
    hidden_service = _service(
        [StoredProcedureSummary(schema_="dbo", name="Hidden")],
        hidden,
    )
    oversized_service = _service(
        [StoredProcedureSummary(schema_="dbo", name="Large")],
        StoredProcedureDefinition(
            schema_="dbo", name="Large", definition="x" * 1025, definition_available=True
        ),
    )

    async def scenario() -> None:
        with pytest.raises(DomainError, match="AMBIGUOUS_OBJECT"):
            await ambiguous.get_stored_procedure("Alpha", "Application", "refresh")
        assert (
            await hidden_service.get_stored_procedure(
                "Alpha", "Application", "hidden", schema="DBO"
            )
        ) is hidden
        with pytest.raises(DomainError) as raised:
            await oversized_service.get_stored_procedure("Alpha", "Application", "large", "dbo")
        assert raised.value.code is ErrorCode.DEFINITION_TOO_LARGE

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (
            OperationalError(
                "SELECT secret", {"password": "hidden"}, Exception("HYT00 query timeout")
            ),
            ErrorCode.TIMEOUT,
        ),
        (SqlAlchemyTimeoutError("pool timeout with secret"), ErrorCode.TIMEOUT),
        (
            OperationalError(
                "SELECT secret",
                {"password": "hidden"},
                Exception(2013, "Lost connection to MySQL server during query (timed out)"),
            ),
            ErrorCode.TIMEOUT,
        ),
        (
            OperationalError(
                "SELECT secret",
                {"password": "hidden"},
                Exception(1044, "Access denied for user 'u'@'%' to database 'secret'"),
            ),
            ErrorCode.ACCESS_DENIED,
        ),
        (
            OperationalError(
                "SELECT secret", {"password": "hidden"}, Exception(1049, "Unknown database 'x'")
            ),
            ErrorCode.CONNECTION_FAILED,
        ),
        (
            DBAPIError(
                "SELECT secret", {"password": "hidden"}, Exception("42000 permission denied")
            ),
            ErrorCode.ACCESS_DENIED,
        ),
        (
            OperationalError(
                "SELECT secret", {"password": "hidden"}, Exception("08001 connection failed")
            ),
            ErrorCode.CONNECTION_FAILED,
        ),
        (
            ProgrammingError(
                "SELECT secret",
                {"password": "hidden"},
                Exception("42000 Cannot open database requested by the login. (4060)"),
            ),
            ErrorCode.CONNECTION_FAILED,
        ),
    ],
)
def test_database_failures_map_to_stable_public_codes(
    failure: BaseException, expected: ErrorCode
) -> None:
    service = _service(failure)

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is expected
        public = str(raised.value)
        assert "SELECT secret" not in public
        assert "password" not in public

    asyncio.run(scenario())


class _OdbcFailure(Exception):
    """Shaped like pyodbc.Error: args are (sqlstate, message)."""


class _PyMySqlFailure(Exception):
    """Shaped like a PyMySQL DBAPI exception: args are (native_code, message)."""


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (_OdbcFailure("HYT00", "localized error"), ErrorCode.TIMEOUT),
        (_OdbcFailure("08004", "localized error"), ErrorCode.CONNECTION_FAILED),
        (_OdbcFailure("28000", "localized error"), ErrorCode.ACCESS_DENIED),
        (_PyMySqlFailure(1044, "localized error"), ErrorCode.ACCESS_DENIED),
        (_PyMySqlFailure(1049, "localized error"), ErrorCode.CONNECTION_FAILED),
    ],
)
def test_database_failure_codes_do_not_depend_on_driver_language(
    failure: BaseException, expected: ErrorCode
) -> None:
    service = _service(DBAPIError("SELECT secret", {"password": "hidden"}, failure))

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is expected

    asyncio.run(scenario())


class _OpaqueFailure(Exception):
    """A driver exception whose args carry nothing; only its text is meaningful."""

    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    def __str__(self) -> str:
        return self.text


class _ArglessOrig:
    """A driver error object without an ``args`` attribute at all."""

    def __str__(self) -> str:
        return "localized error"


@pytest.mark.parametrize(
    ("orig", "expected"),
    [
        (_PyMySqlFailure(-2, "localized error"), ErrorCode.TIMEOUT),
        (_OpaqueFailure("query timeout expired"), ErrorCode.TIMEOUT),
        (_OpaqueFailure("state hyt00 seen"), ErrorCode.TIMEOUT),
        (_OpaqueFailure("state hyt01 seen"), ErrorCode.TIMEOUT),
        (_OdbcFailure("HYT00", "(4060) localized error"), ErrorCode.TIMEOUT),
        (_OdbcFailure("hyt00", "(4060) localized error"), ErrorCode.TIMEOUT),
        (_OpaqueFailure("Cannot open database x"), ErrorCode.CONNECTION_FAILED),
        (_OpaqueFailure("failure (4060)"), ErrorCode.CONNECTION_FAILED),
        (_OpaqueFailure("state 08001 seen"), ErrorCode.CONNECTION_FAILED),
        (_OpaqueFailure("state 08004 seen"), ErrorCode.CONNECTION_FAILED),
        (_OpaqueFailure("permission was denied"), ErrorCode.ACCESS_DENIED),
        (_PyMySqlFailure(4060.0, "localized error"), ErrorCode.DATABASE_ERROR),
        (_PyMySqlFailure(True, "localized error"), ErrorCode.DATABASE_ERROR),
        (_ArglessOrig(), ErrorCode.DATABASE_ERROR),
    ],
    ids=[
        "native-timeout-only",
        "text-timeout",
        "text-hyt00",
        "text-hyt01",
        "upper-sqlstate-beats-native-connection",
        "lower-sqlstate-beats-native-connection",
        "text-cannot-open-database",
        "text-4060",
        "text-08001",
        "text-08004",
        "text-permission-was-denied",
        "float-arg-is-not-a-native-code",
        "bool-arg-is-not-a-native-code",
        "orig-without-args",
    ],
)
def test_each_driver_failure_signal_classifies_on_its_own(
    orig: object, expected: ErrorCode
) -> None:
    service = _service(DBAPIError("SELECT secret", {"password": "hidden"}, cast(Exception, orig)))

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is expected

    asyncio.run(scenario())


def test_an_operational_error_without_a_known_signal_is_a_connection_failure() -> None:
    service = _service(OperationalError("SELECT 1", None, _OpaqueFailure("link lost")))

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is ErrorCode.CONNECTION_FAILED

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("orig", "code", "message", "retryable"),
    [
        (_OdbcFailure("HYT00", "x"), ErrorCode.TIMEOUT, "The database operation timed out.", True),
        (
            _OdbcFailure("08001", "x"),
            ErrorCode.CONNECTION_FAILED,
            "Could not connect to the configured database server.",
            True,
        ),
        (
            _OdbcFailure("28000", "x"),
            ErrorCode.ACCESS_DENIED,
            "The database denied this operation.",
            False,
        ),
        (
            _OpaqueFailure("access denied"),
            ErrorCode.ACCESS_DENIED,
            "The database denied this operation.",
            False,
        ),
    ],
    ids=["timeout", "connection", "denied-by-code", "denied-by-text"],
)
def test_classified_failures_have_a_fixed_public_message_and_retry_flag(
    orig: Exception, code: ErrorCode, message: str, retryable: bool
) -> None:
    service = _service(DBAPIError("SELECT secret", None, orig))

    async def scenario() -> DomainError:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        return raised.value

    error = asyncio.run(scenario())
    assert (error.code, error.public_message, error.hint, error.retryable) == (
        code,
        message,
        None,
        retryable,
    )


def test_connection_code_takes_precedence_over_access_denied_codes() -> None:
    service = _service(
        DBAPIError(
            "SELECT secret",
            {"password": "hidden"},
            _OdbcFailure(
                "28000",
                "Login failed for user. (18456); Cannot open database requested by the login. "
                "(4060)",
            ),
        )
    )

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is ErrorCode.CONNECTION_FAILED

    asyncio.run(scenario())


def test_unstructured_denied_text_is_not_misclassified_as_access_denied() -> None:
    service = _service(
        DBAPIError("SELECT secret", {"password": "hidden"}, Exception("unrelated denied value"))
    )

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is ErrorCode.DATABASE_ERROR

    asyncio.run(scenario())


def test_unexpected_failure_logs_only_generic_context_and_correlation_id(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = _service(RuntimeError("SELECT secret password=hidden"))

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is ErrorCode.DATABASE_ERROR
        assert raised.value.correlation_id is not None

    with caplog.at_level(logging.ERROR, logger="sql_safe_mcp.service"):
        asyncio.run(scenario())

    captured = caplog.text
    assert "Unexpected database operation failure" in captured
    assert "SELECT secret" not in captured
    assert "password" not in captured


def test_ambiguous_table_candidates_omit_null_schema() -> None:
    tables = [
        TableSummary(schema_=None, name="Users"),
        TableSummary(schema_=None, name="users"),
    ]

    with pytest.raises(DomainError) as raised:
        DatabaseService._resolve_table(tables, "users", None)

    assert raised.value.code is ErrorCode.AMBIGUOUS_OBJECT
    assert "None" not in str(raised.value)
    assert "Users" in str(raised.value)


def _login_timeout() -> OperationalError:
    return OperationalError(
        "SELECT secret",
        {"password": "hidden"},
        _OdbcFailure("HYT00", "[HYT00] Login timeout expired for u at alpha (pwd p)"),
    )


def test_timeout_is_logged_with_driver_detail_and_matching_reference(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = _service(_login_timeout())

    async def scenario() -> DomainError:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        return raised.value

    with caplog.at_level(logging.INFO, logger="sql_safe_mcp.service"):
        error = asyncio.run(scenario())

    assert error.code is ErrorCode.TIMEOUT
    assert error.correlation_id is not None
    assert f"Reference: {error.correlation_id}" in str(error)
    line = caplog.text
    assert "operation failed server=Alpha database=- operation=list_databases" in line
    assert "code=TIMEOUT" in line
    assert f"reference={error.correlation_id}" in line
    assert "sqlstate=HYT00" in line
    assert "Login timeout expired" in line
    for leaked in ("SELECT secret", "hidden", " u ", "alpha", "pwd p"):
        assert leaked not in line


def test_connection_failure_gets_a_reference_and_access_denied_does_not(
    caplog: pytest.LogCaptureFixture,
) -> None:
    connection = OperationalError("SELECT 1", None, Exception("08001 connection failed"))
    denied = ProgrammingError("SELECT 1", None, Exception("permission denied"))
    service = _service(connection, denied)

    async def scenario() -> list[DomainError]:
        errors = []
        for _ in range(2):
            with pytest.raises(DomainError) as raised:
                await service.list_databases("Alpha")
            errors.append(raised.value)
        return errors

    with caplog.at_level(logging.INFO, logger="sql_safe_mcp.service"):
        failed, refused = asyncio.run(scenario())

    assert failed.code is ErrorCode.CONNECTION_FAILED and failed.correlation_id
    assert refused.code is ErrorCode.ACCESS_DENIED and refused.correlation_id is None
    assert "code=CONNECTION_FAILED" in caplog.text
    assert "code=ACCESS_DENIED" in caplog.text


def test_pool_timeout_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    service = _service(SqlAlchemyTimeoutError("QueuePool limit of size 2 overflow 2 reached"))

    async def scenario() -> None:
        with pytest.raises(DomainError) as raised:
            await service.list_databases("Alpha")
        assert raised.value.code is ErrorCode.TIMEOUT

    with caplog.at_level(logging.INFO, logger="sql_safe_mcp.service"):
        asyncio.run(scenario())

    assert "code=TIMEOUT" in caplog.text
    assert "QueuePool limit" in caplog.text


def test_successful_operation_is_logged_with_elapsed(caplog: pytest.LogCaptureFixture) -> None:
    service = _service(["master"])

    with caplog.at_level(logging.INFO, logger="sql_safe_mcp.service"):
        asyncio.run(service.list_databases("Alpha"))

    assert (
        "operation ok server=Alpha database=- operation=list_databases elapsed_ms=" in caplog.text
    )


def test_unexpected_failure_log_names_only_the_exception_class(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = _service(RuntimeError("SELECT secret password=hidden"))

    async def scenario() -> None:
        with pytest.raises(DomainError):
            await service.list_databases("Alpha")

    with caplog.at_level(logging.INFO, logger="sql_safe_mcp.service"):
        asyncio.run(scenario())

    assert "operation=list_databases" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "hidden" not in caplog.text
