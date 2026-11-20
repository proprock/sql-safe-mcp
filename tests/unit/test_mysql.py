from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any, cast

import pytest
from sqlalchemy import Connection

from sql_safe_mcp.db.extras import extras_for
from sql_safe_mcp.db.mysql import MySqlExtras
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


@pytest.mark.parametrize("engine", ["mysql", "mariadb"])
def test_extras_for_returns_mysql_extras(engine: str) -> None:
    assert isinstance(extras_for(engine), MySqlExtras)


def test_list_databases_excludes_system_schemas_with_binds() -> None:
    connection, recording = _connection(
        [SimpleNamespace(name="app"), SimpleNamespace(name="warehouse")]
    )

    names = MySqlExtras().list_databases(connection)

    assert names == ["app", "warehouse"]
    statement, parameters = recording.calls[0]
    assert "information_schema.SCHEMATA" in statement
    assert parameters is not None
    assert set(parameters.values()) == {
        "information_schema",
        "mysql",
        "performance_schema",
        "sys",
    }


def test_list_stored_procedures_has_null_schema_and_binds_database() -> None:
    connection, recording = _connection(
        [SimpleNamespace(procedure_name="refresh"), SimpleNamespace(procedure_name="write_event")]
    )

    procedures = MySqlExtras().list_stored_procedures(connection, "app")

    assert [(item.schema_, item.name) for item in procedures] == [
        (None, "refresh"),
        (None, "write_event"),
    ]
    statement, parameters = recording.calls[0]
    assert "ROUTINE_TYPE = 'PROCEDURE'" in statement
    assert parameters == {"database": "app"}


def test_get_stored_procedure_rejects_schema_without_querying() -> None:
    connection, recording = _connection()

    assert MySqlExtras().get_stored_procedure(connection, "app", "dbo", "refresh") is None
    assert recording.calls == []


def test_get_stored_procedure_uses_binds_and_normalizes_definition() -> None:
    connection, recording = _connection(
        [SimpleNamespace(procedure_name="refresh", definition="BEGIN SELECT 1; END")]
    )

    definition = MySqlExtras().get_stored_procedure(connection, "app", None, "refresh")

    assert definition is not None
    assert definition.schema_ is None
    assert definition.name == "refresh"
    assert definition.definition == "BEGIN SELECT 1; END"
    assert definition.definition_available is True
    assert recording.calls[0][1] == {"database": "app", "name": "refresh"}


def test_get_stored_procedure_hidden_definition_is_unavailable() -> None:
    connection, _ = _connection([SimpleNamespace(procedure_name="refresh", definition=None)])

    definition = MySqlExtras().get_stored_procedure(connection, "app", None, "refresh")

    assert definition is not None
    assert definition.definition is None
    assert definition.definition_available is False


def test_get_stored_procedure_missing_returns_none() -> None:
    connection, _ = _connection([])

    assert MySqlExtras().get_stored_procedure(connection, "app", None, "missing") is None


@pytest.mark.parametrize("name", ["app", "Billing"])
def test_current_database_returns_the_name_the_server_resolved(name: str) -> None:
    connection, recording = _connection([(name,)])

    assert MySqlExtras().current_database(connection) == name
    assert recording.calls == [("SELECT DATABASE()", None)]


def test_current_database_rejects_no_selected_database() -> None:
    connection, _ = _connection([(None,)])

    with pytest.raises(DomainError) as info:
        MySqlExtras().current_database(connection)
    assert info.value.code is ErrorCode.DATABASE_ERROR
