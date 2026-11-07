from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class OutputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ServerSummary(OutputModel):
    name: str
    engine: Literal["sqlserver", "mysql", "mariadb"]
    access_level: Literal["metadata", "meta_and_code", "all_pii_safe"]


class ServerList(OutputModel):
    servers: list[ServerSummary]


class DatabaseSummary(OutputModel):
    name: str


class DatabaseList(OutputModel):
    databases: list[DatabaseSummary]


class TableSummary(OutputModel):
    schema_: str | None = Field(alias="schema")
    name: str


class TableList(OutputModel):
    tables: list[TableSummary]


class ColumnDefinition(OutputModel):
    name: str
    native_type: str
    nullable: bool
    length: int | None = None
    precision: int | None = None
    scale: int | None = None
    autoincrement: bool | str | None = None
    identity: dict[str, Any] | None = None
    computed: dict[str, Any] | None = None
    default: str | None = None


class PrimaryKeyDefinition(OutputModel):
    name: str | None = None
    columns: list[str]


class ForeignKeyDefinition(OutputModel):
    name: str | None = None
    columns: list[str]
    referred_schema: str | None = None
    referred_table: str
    referred_columns: list[str]
    options: dict[str, Any] = Field(default_factory=dict)


class UniqueConstraintDefinition(OutputModel):
    name: str | None = None
    columns: list[str]


class IndexDefinition(OutputModel):
    name: str | None = None
    columns: list[str | None]
    unique: bool = False
    expressions: list[str] = Field(default_factory=list)


class TableDefinition(OutputModel):
    schema_: str | None = Field(alias="schema")
    name: str
    columns: list[ColumnDefinition]
    primary_key: PrimaryKeyDefinition
    foreign_keys: list[ForeignKeyDefinition]
    unique_constraints: list[UniqueConstraintDefinition]
    indexes: list[IndexDefinition]


class StoredProcedureSummary(OutputModel):
    schema_: str | None = Field(alias="schema")
    name: str


class StoredProcedureList(OutputModel):
    stored_procedures: list[StoredProcedureSummary]


class StoredProcedureDefinition(OutputModel):
    schema_: str | None = Field(alias="schema")
    name: str
    definition: str | None
    definition_available: bool


ResultEncoding = Literal[
    "json", "token", "decimal", "date", "time", "datetime", "uuid", "base64", "suppressed"
]


class ColumnSource(OutputModel):
    schema_: str | None = Field(alias="schema")
    table: str
    column: str


class SqlColumn(OutputModel):
    name: str
    source: ColumnSource | None
    protected: bool
    encoding: ResultEncoding


class SqlResult(OutputModel):
    columns: list[SqlColumn]
    rows: list[list[Any]]
    row_count: int
    truncated: bool
