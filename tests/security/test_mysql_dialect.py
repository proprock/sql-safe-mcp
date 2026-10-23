"""The shared validation pipeline on the MySQL/MariaDB dialect (`mysql`)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar

import pytest
import sqlglot
from support import ALIAS, DATABASE, OWN, RUNTIME
from typed_columns import typed

from sql_safe_mcp.config import PiiConfig, PiiRule
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import MYSQL, SQLSERVER, dialect_for
from sql_safe_mcp.security.lineage import _cross_check
from sql_safe_mcp.security.pipeline import validate_sql
from sql_safe_mcp.security.schema import ColumnSchema, TableSchema
from sql_safe_mcp.security.validated_query import ValidatedQuery

MYSQL_PII = PiiConfig(rules=[PiiRule(database="*", table="users", columns=["email", "phone"])])


class MysqlCatalog:
    """MySQL has no schema level: reflection reports an empty schema for every table."""

    tables: ClassVar[dict[str, list[str]]] = {
        "users": ["id", "email", "phone", "name"],
        "orders": ["id", "userid", "total"],
        "canary": ["id"],
    }

    def list_tables(self) -> list[tuple[str, str]]:
        return [("", name) for name in self.tables]

    def columns(self, schema: str, table: str) -> Sequence[ColumnSchema]:
        assert schema == ""
        return typed(self.tables[table])


def validate(sql: str, max_rows: int = 200) -> ValidatedQuery:
    return validate_sql(
        sql,
        alias=ALIAS,
        database=DATABASE,
        catalog=MysqlCatalog(),
        pii_config=MYSQL_PII,
        codec=OWN,
        runtime=RUNTIME,
        max_rows=max_rows,
        dialect=MYSQL,
    )


def rejected(sql: str) -> DomainError:
    with pytest.raises(DomainError) as info:
        validate(sql)
    assert info.value.code is ErrorCode.QUERY_REJECTED
    return info.value


def test_dialect_comes_from_the_engine() -> None:
    assert dialect_for("sqlserver") is SQLSERVER
    assert dialect_for("mysql") is MYSQL
    assert dialect_for("mariadb") is MYSQL
    with pytest.raises(ValueError, match="unsupported engine 'postgres'"):
        dialect_for("postgres")


def test_generated_sql_uses_backticks_limit_and_percent_s_markers() -> None:
    token = OWN.encrypt("a@example.com")

    query = validate(f"SELECT u.id, u.email FROM users u WHERE u.email = '{token}' AND u.id = 7")

    assert query.sql == (
        "SELECT `u`.`id`, `u`.`email` FROM `users` AS u "
        "WHERE `u`.`email` = %s AND `u`.`id` = 7 LIMIT 201"
    )
    assert query.sql.count("%s") == 1
    assert query.parameters == ("a@example.com",)
    assert token not in query.sql
    assert [output.protected for output in query.outputs] == [False, True]


def test_star_expands_and_row_cap_uses_limit() -> None:
    query = validate("SELECT * FROM users", max_rows=5)

    assert query.sql.endswith("LIMIT 6")
    assert "TOP" not in query.sql
    assert [output.label for output in query.outputs] == ["id", "email", "phone", "name"]
    assert all(
        output.source is not None and output.source.schema == "" for output in query.outputs[:1]
    )


def test_requested_limit_is_capped_not_raised() -> None:
    assert validate("SELECT id FROM users LIMIT 3", max_rows=5).sql.endswith("LIMIT 3")
    assert validate("SELECT id FROM users LIMIT 500", max_rows=5).sql.endswith("LIMIT 6")


def test_generated_sql_reparses_and_revalidates() -> None:
    query = validate("SELECT u.id FROM users u JOIN orders o ON o.userid = u.id WHERE o.id > 1")

    reparsed = sqlglot.parse_one(query.sql.replace("%s", "1"), dialect="mysql")

    assert reparsed.sql(dialect="mysql") == query.sql.replace("%s", "1")


def test_literal_percent_is_doubled_for_the_driver() -> None:
    query = validate("SELECT id FROM users WHERE name = '100%'")

    assert "'100%%'" in query.sql
    assert query.parameters == ()


def test_injection_after_decrypt_stays_one_bind_value() -> None:
    payload = "x'; DROP TABLE canary;--"
    token = OWN.encrypt(payload)

    query = validate(f"SELECT id FROM users WHERE email = '{token}'")

    assert query.parameters == (payload,)
    assert "DROP" not in query.sql
    assert query.sql.count("%s") == 1


def test_backslash_in_a_literal_is_escaped_in_generated_sql() -> None:
    query = validate("SELECT id FROM users WHERE name = 'a\\\\'")

    reparsed = sqlglot.parse_one(query.sql, dialect="mysql")
    assert reparsed.sql(dialect="mysql") == query.sql
    assert "a\\\\" in query.sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM app.users",
        "SELECT id FROM mysql.user",
        "SELECT id FROM information_schema.tables",
        "SELECT id FROM app.dbo.users",
        "SELECT id FROM `app`.`users`",
        "SELECT id FROM users, orders",
        "SELECT id FROM missing",
        "SELECT TOP 5 id FROM users",
        "SELECT id FROM users LIMIT 5, 10",
        "SELECT id FROM users LIMIT 5 OFFSET 10",
        "SELECT id FROM users LIMIT ALL",
        "SELECT SLEEP(5)",
        "SELECT id FROM users WHERE id = @x",
        "SELECT id FROM users WHERE id = (SELECT 1)",
        "SELECT id FROM users FOR UPDATE",
        "SELECT id FROM users LOCK IN SHARE MODE",
        "SELECT id INTO OUTFILE '/tmp/x' FROM users",
        "SELECT id FROM users PROCEDURE ANALYSE()",
        "SELECT /*+ MAX_EXECUTION_TIME(1) */ id FROM users",
        "SELECT id FROM users USE INDEX (idx)",
        "SELECT id FROM users PARTITION (p0)",
        "SELECT id FROM users UNION SELECT id FROM orders",
        "SELECT id FROM users; DROP TABLE canary",
        "SELECT email FROM users WHERE email = 'plain@example.com'",
        "SELECT id FROM users ORDER BY email",
        "SELECT id FROM users JOIN orders ON orders.total = users.email",
        "SELECT LOWER(email) FROM users",
        "SELECT 1 FROM users WHERE `id` = 1 AND `email` LIKE '%a%'",
    ],
)
def test_mysql_specific_constructs_are_rejected(sql: str) -> None:
    rejected(sql)


def test_versioned_comments_never_reach_generated_sql() -> None:
    query = validate("SELECT id /*!50000 , email */ FROM users # trailing\n WHERE id = 1")

    assert "50000" not in query.sql
    assert "email" not in query.sql
    assert "#" not in query.sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id /* /* */ FROM users WHERE name = 'p*/ ; DROP TABLE canary; --'",
        "SELECT id FROM users # ; DROP TABLE canary",
        'SELECT "id""; DROP TABLE canary; --" FROM users',
    ],
)
def test_tsql_attack_shapes_are_one_safe_statement_in_mysql(sql: str) -> None:
    query = validate(sql)

    statements = sqlglot.parse(query.sql.replace("%%", "%"), dialect="mysql")
    assert len(statements) == 1
    assert statements[0] is not None
    stripped = statements[0].copy()
    for literal in list(stripped.find_all(sqlglot.exp.Literal)):
        literal.replace(sqlglot.exp.Null())
    outside_literals = stripped.sql(dialect="mysql")
    assert ";" not in outside_literals
    assert "DROP" not in outside_literals


def test_count_star_is_allowed_and_keeps_its_shape() -> None:
    token = OWN.encrypt("a@example.com")

    plain = validate("SELECT COUNT(*) FROM users")
    aliased = validate(f"SELECT COUNT(*) AS n FROM users WHERE email = '{token}'")

    assert plain.sql == "SELECT COUNT(*) FROM `users` LIMIT 201"
    assert [output.kind for output in plain.outputs] == ["count"]
    assert aliased.sql.startswith("SELECT COUNT(*) AS n FROM `users`")
    assert aliased.parameters == ("a@example.com",)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT COUNT(id) FROM users",
        "SELECT COUNT(DISTINCT id) FROM users",
        "SELECT COUNT(email) FROM users",
        "SELECT COUNT(*), COUNT(*) FROM users GROUP BY id",
    ],
)
def test_only_plain_count_star_is_allowed(sql: str) -> None:
    rejected(sql)


def _mysql_select(sql: str) -> Any:
    return sqlglot.parse_one(sql, dialect="mysql")


def test_second_opinion_uses_a_flat_catalog_on_mysql() -> None:
    tables = (TableSchema("", "users", tuple(typed(["id", "email"]))),)

    _cross_check(_mysql_select("SELECT `users`.`id` FROM `users`"), tables, MYSQL)
    with pytest.raises(DomainError) as info:
        _cross_check(_mysql_select("SELECT `users`.`nope` FROM `users`"), tables, MYSQL)
    assert info.value.code is ErrorCode.QUERY_REJECTED
