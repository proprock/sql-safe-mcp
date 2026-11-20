from __future__ import annotations

from typing import Protocol

from sqlalchemy import Connection, text

from sql_safe_mcp.errors import DomainError
from sql_safe_mcp.models import StoredProcedureDefinition, StoredProcedureSummary


class DatabaseExtras(Protocol):
    def list_databases(self, connection: Connection) -> list[str]: ...

    def current_database(self, connection: Connection) -> str:
        """Name of the database the connection is actually using, as the server spells it."""
        ...

    def list_stored_procedures(
        self, connection: Connection, database: str
    ) -> list[StoredProcedureSummary]: ...

    def get_stored_procedure(
        self,
        connection: Connection,
        database: str,
        schema: str | None,
        name: str,
    ) -> StoredProcedureDefinition | None: ...


def read_database_name(connection: Connection, statement: str) -> str:
    """Run a fixed one-value statement that names the current database; NULL is a failure."""
    row = connection.execute(text(statement)).first()
    if row is None or row[0] is None:
        raise DomainError.unexpected()
    return str(row[0])


def extras_for(engine: str) -> DatabaseExtras:
    if engine == "sqlserver":
        from sql_safe_mcp.db.sqlserver import SqlServerExtras

        return SqlServerExtras()
    if engine in ("mysql", "mariadb"):
        from sql_safe_mcp.db.mysql import MySqlExtras

        return MySqlExtras()
    raise ValueError(f"unsupported engine {engine!r}")
