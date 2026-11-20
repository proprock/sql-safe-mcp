"""Test double for DatabaseExtras.current_database, the server-resolved database name."""

from __future__ import annotations

from typing import Any, cast

from sql_safe_mcp.db.extras import DatabaseExtras


class NamedDatabase:
    """Reports a fixed canonical name and counts how often the server was asked for it."""

    def __init__(self, name: str = "d") -> None:
        self.name = name
        self.calls = 0
        self.connections: list[Any] = []

    def current_database(self, connection: Any) -> str:
        self.calls += 1
        self.connections.append(connection)
        return self.name


def extras(name: str = "d") -> DatabaseExtras:
    return cast(DatabaseExtras, NamedDatabase(name))
