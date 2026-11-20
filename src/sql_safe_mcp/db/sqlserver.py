from __future__ import annotations

from sqlalchemy import Connection, text

from sql_safe_mcp.db.extras import DatabaseExtras, read_database_name
from sql_safe_mcp.models import StoredProcedureDefinition, StoredProcedureSummary


class SqlServerExtras(DatabaseExtras):
    def current_database(self, connection: Connection) -> str:
        return read_database_name(connection, "SELECT DB_NAME()")

    def list_databases(self, connection: Connection) -> list[str]:
        rows = connection.execute(
            text(
                "SELECT name FROM sys.databases "
                "WHERE state = 0 AND HAS_DBACCESS(name) = 1 ORDER BY name"
            )
        )
        return [str(row.name) for row in rows]

    def list_stored_procedures(
        self, connection: Connection, database: str
    ) -> list[StoredProcedureSummary]:
        del database
        rows = connection.execute(
            text(
                "SELECT s.name AS schema_name, p.name AS procedure_name "
                "FROM sys.procedures AS p "
                "JOIN sys.schemas AS s ON s.schema_id = p.schema_id "
                "WHERE p.is_ms_shipped = 0 "
                "ORDER BY s.name, p.name"
            )
        )
        return [
            StoredProcedureSummary(schema_=str(row.schema_name), name=str(row.procedure_name))
            for row in rows
        ]

    def get_stored_procedure(
        self,
        connection: Connection,
        database: str,
        schema: str | None,
        name: str,
    ) -> StoredProcedureDefinition | None:
        del database
        if schema is None:
            return None
        row = connection.execute(
            text(
                "SELECT s.name AS schema_name, p.name AS procedure_name, "
                "OBJECT_DEFINITION(p.object_id) AS definition "
                "FROM sys.procedures AS p "
                "JOIN sys.schemas AS s ON s.schema_id = p.schema_id "
                "WHERE s.name = :schema AND p.name = :name AND p.is_ms_shipped = 0"
            ),
            {"schema": schema, "name": name},
        ).first()
        if row is None:
            return None
        definition = None if row.definition is None else str(row.definition)
        return StoredProcedureDefinition(
            schema_=str(row.schema_name),
            name=str(row.procedure_name),
            definition=definition,
            definition_available=definition is not None,
        )
