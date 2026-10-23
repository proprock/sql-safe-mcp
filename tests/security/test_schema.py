from collections.abc import Mapping, Sequence

import pytest
import sqlalchemy as sa
from sqlglot import exp
from typed_columns import typed

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.parser import ParserLimits, parse_select
from sql_safe_mcp.security.schema import (
    ColumnSchema,
    ReflectedCatalog,
    SchemaCache,
    TableSchema,
    resolve_tables,
    type_class,
)

LIMITS = ParserLimits(4096, 500, 4, 10)


class FakeCatalog:
    def __init__(self, tables: Mapping[tuple[str, str], Sequence[str]]) -> None:
        self._tables = tables
        self.column_lookups: list[tuple[str, str]] = []

    def list_tables(self) -> list[tuple[str, str]]:
        return list(self._tables)

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        self.column_lookups.append((schema, table))
        return typed(self._tables[(schema, table)])


CATALOG = {
    ("dbo", "Users"): ["Id", "Email"],
    ("dbo", "Orders"): ["Id", "UserId"],
    ("sales", "Orders"): ["Id", "Total"],
    ("dbo", "select"): ["from"],
    ("dbo", "Ünï"): ["Ç"],
}


def resolve(sql: str, tables: Mapping[tuple[str, str], Sequence[str]] | None = None):
    query = parse_select(sql, LIMITS)
    catalog = FakeCatalog(CATALOG if tables is None else tables)
    return query, resolve_tables(query, catalog), catalog


def rejected(sql: str) -> DomainError:
    with pytest.raises(DomainError) as info:
        resolve(sql)
    assert info.value.code is ErrorCode.QUERY_REJECTED
    return info.value


def test_resolves_qualified_table_case_insensitively() -> None:
    _, tables, _ = resolve("SELECT * FROM DBO.users")
    assert tables == (TableSchema("dbo", "Users", tuple(typed(["Id", "Email"]))),)


def test_unqualified_table_with_single_match() -> None:
    _, tables, _ = resolve("SELECT * FROM users")
    assert tables[0].schema == "dbo"


def test_unqualified_ambiguous_table_is_rejected() -> None:
    rejected("SELECT * FROM Orders")


def test_qualified_ambiguity_is_resolved_by_schema() -> None:
    _, tables, _ = resolve("SELECT * FROM sales.orders")
    assert tables[0] == TableSchema("sales", "Orders", tuple(typed(["Id", "Total"])))


def test_case_variants_that_collide_are_rejected() -> None:
    rejected_tables = {("dbo", "Users"): ["a"], ("dbo", "USERS"): ["a"]}
    with pytest.raises(DomainError):
        resolve("SELECT * FROM dbo.users", rejected_tables)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM Missing",
        "SELECT * FROM dbo.Missing",
        "SELECT * FROM nope.Users",
        "SELECT * FROM sys.objects",
        "SELECT * FROM INFORMATION_SCHEMA.TABLES",
        "SELECT * FROM otherdb.dbo.Users",
    ],
)
def test_missing_system_and_cross_database_objects_are_rejected(sql: str) -> None:
    rejected(sql)


def test_bracketed_and_reserved_word_identifiers() -> None:
    _, tables, _ = resolve("SELECT [from] FROM [dbo].[select]")
    assert tables[0].name == "select"


def test_unicode_identifiers_use_case_folding() -> None:
    _, tables, _ = resolve("SELECT * FROM dbo.[ÜNÏ]")
    assert tables[0].name == "Ünï"


def test_resolution_rewrites_tables_to_reflected_names() -> None:
    query, _, _ = resolve("SELECT * FROM DBO.users AS u JOIN sales.ORDERS ON 1 = 1")
    names = [(table.db, table.name) for table in query.find_all(exp.Table)]
    assert names == [("dbo", "Users"), ("sales", "Orders")]
    assert all(table.this.args.get("quoted") for table in query.find_all(exp.Table))


def test_only_referenced_tables_are_loaded() -> None:
    _, _, catalog = resolve("SELECT * FROM dbo.Users")
    assert catalog.column_lookups == [("dbo", "Users")]


def test_repeated_table_is_resolved_per_reference() -> None:
    _, tables, _ = resolve("SELECT a.Id FROM dbo.Users a JOIN dbo.Users b ON a.Id = b.Id")
    assert len(tables) == 2


def test_cache_is_bounded_and_evicts_least_recently_used() -> None:
    cache = SchemaCache(max_entries=2, ttl_seconds=60)
    cache.put(("a", "d", 1), ("x",))
    cache.put(("a", "d", 2), ("y",))
    assert cache.get(("a", "d", 1)) == ("x",)
    cache.put(("a", "d", 3), ("z",))
    assert cache.get(("a", "d", 2)) is None
    assert cache.get(("a", "d", 1)) == ("x",)


def test_cache_entries_expire() -> None:
    now = [0.0]
    cache = SchemaCache(max_entries=4, ttl_seconds=10, clock=lambda: now[0])
    cache.put("k", ("v",))
    now[0] = 9.9
    assert cache.get("k") == ("v",)
    now[0] = 10.1
    assert cache.get("k") is None


@pytest.fixture
def sqlite_connection():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(sa.text("CREATE TABLE Users (Id INTEGER, Email TEXT)"))
        connection.execute(sa.text("CREATE VIEW V AS SELECT Id FROM Users"))
        yield connection
    engine.dispose()


def test_reflected_catalog_lists_base_tables_and_columns(sqlite_connection) -> None:
    catalog = ReflectedCatalog(sqlite_connection, SchemaCache(8, 60), "srv", "db")
    assert catalog.list_tables() == [("main", "Users")]
    assert list(catalog.columns("main", "Users")) == [
        ColumnSchema("Id", "integer"),
        ColumnSchema("Email", "string"),
    ]


def test_reflected_catalog_uses_cache_and_isolates_scopes(sqlite_connection) -> None:
    cache = SchemaCache(8, 60)
    first = ReflectedCatalog(sqlite_connection, cache, "srv", "db")
    first.list_tables()
    sqlite_connection.execute(sa.text("CREATE TABLE Later (Id INTEGER)"))
    assert first.list_tables() == [("main", "Users")]
    other_alias = ReflectedCatalog(sqlite_connection, cache, "srv2", "db")
    assert ("main", "Later") in other_alias.list_tables()
    other_database = ReflectedCatalog(sqlite_connection, cache, "srv", "db2")
    assert ("main", "Later") in other_database.list_tables()


def test_missing_table_columns_are_rejected(sqlite_connection) -> None:
    catalog = ReflectedCatalog(sqlite_connection, SchemaCache(8, 60), "srv", "db")
    with pytest.raises(DomainError) as info:
        catalog.columns("main", "Gone")
    assert info.value.code is ErrorCode.QUERY_REJECTED


@pytest.mark.parametrize(
    ("column_type", "expected"),
    [
        (sa.String(10), "string"),
        (sa.Text(), "string"),
        (sa.Integer(), "integer"),
        (sa.BigInteger(), "integer"),
        (sa.Float(), "float"),
        (sa.Numeric(12, 2), "decimal"),
        (sa.Boolean(), "bool"),
        (sa.Date(), "date"),
        (sa.Time(), "time"),
        (sa.DateTime(), "datetime"),
        (sa.Uuid(), "uuid"),
        (sa.LargeBinary(), "binary"),
        (sa.JSON(), "other"),
        (sa.types.NullType(), "other"),
        (None, "other"),
    ],
)
def test_reflected_types_map_to_token_classes(column_type: object, expected: str) -> None:
    assert type_class(column_type) == expected
