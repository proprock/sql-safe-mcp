from __future__ import annotations

from sqlalchemy import Connection, text

from sql_safe_mcp.db.extras import DatabaseExtras, read_database_name
from sql_safe_mcp.models import StoredProcedureDefinition, StoredProcedureSummary

SYSTEM_DATABASES = ("information_schema", "mysql", "performance_schema", "sys")


class MySqlExtras(DatabaseExtras):
    """MySQL and MariaDB: a database is the catalog, there is no separate schema."""

    def current_database(self, connection: Connection) -> str:
        return read_database_name(connection, "SELECT DATABASE()")

    def list_databases(self, connection: Connection) -> list[str]:
        rows = connection.execute(
            text(
                "SELECT SCHEMA_NAME AS name FROM information_schema.SCHEMATA "
                "WHERE SCHEMA_NAME NOT IN (:s0, :s1, :s2, :s3) ORDER BY SCHEMA_NAME"
            ),
            {f"s{index}": name for index, name in enumerate(SYSTEM_DATABASES)},
        )
        return [str(row.name) for row in rows]

    def list_stored_procedures(
        self, connection: Connection, database: str
    ) -> list[StoredProcedureSummary]:
        rows = connection.execute(
            text(
                "SELECT ROUTINE_NAME AS procedure_name FROM information_schema.ROUTINES "
                "WHERE ROUTINE_SCHEMA = :database AND ROUTINE_TYPE = 'PROCEDURE' "
                "ORDER BY ROUTINE_NAME"
            ),
            {"database": database},
        )
        return [StoredProcedureSummary(schema_=None, name=str(row.procedure_name)) for row in rows]

    def get_stored_procedure(
        self,
        connection: Connection,
        database: str,
        schema: str | None,
        name: str,
    ) -> StoredProcedureDefinition | None:
        if schema is not None:
            return None
        row = connection.execute(
            text(
                "SELECT ROUTINE_NAME AS procedure_name, ROUTINE_DEFINITION AS definition "
                "FROM information_schema.ROUTINES "
                "WHERE ROUTINE_SCHEMA = :database AND ROUTINE_NAME = :name "
                "AND ROUTINE_TYPE = 'PROCEDURE'"
            ),
            {"database": database, "name": name},
        ).first()
        if row is None:
            return None
        definition = None if row.definition is None else str(row.definition)
        return StoredProcedureDefinition(
            schema_=None,
            name=str(row.procedure_name),
            definition=definition,
            definition_available=definition is not None,
        )
