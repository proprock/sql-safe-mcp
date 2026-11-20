from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy import Connection

from sql_safe_mcp.db.sqlserver import SqlServerExtras
from sql_safe_mcp.errors import DomainError, ErrorCode


class FakeResult:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows

    def __iter__(self) -> Iterator[object]:
        return iter(self.rows)

    def first(self) -> object | None:
        return self.rows[0] if self.rows else None


class RecordingConnection:
    def __init__(self, responses: list[list[object]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    def execute(self, statement: object, parameters: dict[str, Any] | None = None) -> FakeResult:
        self.calls.append((str(statement), parameters))
        return FakeResult(self.responses.pop(0))


def _connection(*responses: list[object]) -> tuple[Connection, RecordingConnection]:
    recording = RecordingConnection(list(responses))
    return cast(Connection, recording), recording


def test_list_databases_normalizes_rows() -> None:
    connection, recording = _connection(
        [SimpleNamespace(name="master"), SimpleNamespace(name="Warehouse")]
    )

    names = SqlServerExtras().list_databases(connection)

    assert names == ["master", "Warehouse"]
    assert "HAS_DBACCESS(name) = 1" in recording.calls[0][0]
    assert recording.calls[0][1] is None


def test_list_stored_procedures_normalizes_schema_and_name() -> None:
    connection, recording = _connection(
        [
            SimpleNamespace(schema_name="dbo", procedure_name="RefreshCache"),
            SimpleNamespace(schema_name="audit", procedure_name="WriteEvent"),
        ]
    )

    procedures = SqlServerExtras().list_stored_procedures(connection, "Application")

    assert [(item.schema_, item.name) for item in procedures] == [
        ("dbo", "RefreshCache"),
        ("audit", "WriteEvent"),
    ]
    assert "sys.procedures" in recording.calls[0][0]
    assert recording.calls[0][1] is None


def test_get_stored_procedure_uses_binds_and_normalizes_visible_definition() -> None:
    connection, recording = _connection(
        [
            SimpleNamespace(
                schema_name="dbo",
                procedure_name="RefreshCache",
                definition="CREATE PROCEDURE dbo.RefreshCache AS SELECT 1",
            )
        ]
    )

    definition = SqlServerExtras().get_stored_procedure(
        connection, "Application", "dbo", "RefreshCache"
    )

    assert definition is not None
    assert definition.definition_available is True
    assert definition.definition == "CREATE PROCEDURE dbo.RefreshCache AS SELECT 1"
    statement, parameters = recording.calls[0]
    assert "s.name = :schema" in statement
    assert "p.name = :name" in statement
    assert parameters == {"schema": "dbo", "name": "RefreshCache"}
    assert "RefreshCache" not in statement


def test_get_stored_procedure_allows_hidden_definition() -> None:
    connection, _recording = _connection(
        [SimpleNamespace(schema_name="dbo", procedure_name="Hidden", definition=None)]
    )

    definition = SqlServerExtras().get_stored_procedure(connection, "Application", "dbo", "Hidden")

    assert definition is not None
    assert definition.definition is None
    assert definition.definition_available is False


def test_get_stored_procedure_returns_none_for_missing_or_unqualified_name() -> None:
    connection, recording = _connection([])
    extras = SqlServerExtras()

    assert extras.get_stored_procedure(connection, "Application", None, "Missing") is None
    assert recording.calls == []
    assert extras.get_stored_procedure(connection, "Application", "dbo", "Missing") is None


def test_current_database_returns_the_name_the_server_resolved() -> None:
    connection, recording = _connection([("Billing",)])

    assert SqlServerExtras().current_database(connection) == "Billing"
    assert recording.calls == [("SELECT DB_NAME()", None)]


def test_current_database_rejects_a_missing_name() -> None:
    connection, _ = _connection([(None,)])

    with pytest.raises(DomainError) as info:
        SqlServerExtras().current_database(connection)
    assert info.value.code is ErrorCode.DATABASE_ERROR
