"""Hypothesis property bodies on the mysql dialect (shared by the fast and deep suites).

Any minimized failing example found here must be added to tests/security/corpus_mysql.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from property_checks import with_tokens
from sqlglot import exp, parse_one
from support import (
    _FROM_KW,
    _SELECT_KW,
    ALIAS,
    DATABASE,
    OWN,
    RUNTIME,
    Spec,
    SpyConnection,
    _sub,
    render,
    validate,
)
from support_mysql import spy_mysql_service, validate_mysql

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import MYSQL
from sql_safe_mcp.security.parser import ParserLimits, parse_select, validate_allowlist
from sql_safe_mcp.security.tokens import PREFIX
from sql_safe_mcp.security.validated_query import ValidatedQuery

SPY = SpyConnection()
SERVICE = spy_mysql_service(SPY)
_USERS_ALIAS = r"\bUsers(?:\s|/\*c\*/|--\s?c\n|#c\n)+u\b"

# Each mutation injects one construct the mysql dialect must reject; none may be a silent no-op.
MYSQL_FORBIDDEN_MUTATIONS: list[Callable[[str], str]] = [
    lambda s: s + " UNION SELECT 1",
    lambda s: s + "; DROP TABLE Canary",
    lambda s: s + " FOR UPDATE",
    lambda s: s + " LOCK IN SHARE MODE",
    lambda s: s + " INTO OUTFILE '/tmp/x'",
    lambda s: _sub(_USERS_ALIAS, "Users u USE INDEX (PRIMARY)", s),
    lambda s: _sub(_USERS_ALIAS, "mysql.Users u", s),
    lambda s: _sub(_USERS_ALIAS, "app.Users u", s),
    lambda s: _sub(_USERS_ALIAS, "(SELECT Id FROM Users) u", s),
    lambda s: _sub(_SELECT_KW, "SELECT DISTINCT", s),
    lambda s: _sub(_SELECT_KW, "SELECT SLEEP(1),", s),
    lambda s: _sub(_SELECT_KW, "SELECT (SELECT 1),", s),
    lambda s: _sub(_SELECT_KW, "SELECT @@version,", s),
    lambda s: _sub(_SELECT_KW, "SELECT @a := 1,", s),
    lambda s: _sub(_SELECT_KW, "SELECT CASE WHEN 1 = 1 THEN 1 END,", s),
    lambda s: _sub(_SELECT_KW, "WITH c AS (SELECT 1 AS n) SELECT", s),
    lambda s: _sub(_SELECT_KW, "SELECT SUM(u.Id),", s),
    lambda s: _sub(_SELECT_KW, "SELECT STRAIGHT_JOIN", s),
    lambda s: _sub(_FROM_KW, "INTO @v FROM", s),
    lambda s: _sub(_USERS_ALIAS, "Users u, Orders x", s),
    lambda s: "DELETE FROM Canary; " + s,
    lambda s: "CALL cleanup(); " + s,
]


def _render(spec: Spec, seed: int, alias_style: int = 0) -> str:
    return render(spec, seed, alias_style, dialect=MYSQL)


def decision(sql: str) -> tuple[Any, ...]:
    query = validate_mysql(sql)
    outputs = tuple((o.label, o.kind, o.source, o.protected) for o in query.outputs)
    return query.sql, query.parameters, outputs


def check_valid_specs_are_accepted(spec: Spec, seed: int) -> None:
    query = validate_mysql(_render(spec, seed))
    assert " LIMIT " in query.sql
    assert query.sql.count("%s") == len(query.parameters)


def check_formatting_does_not_change_the_decision(spec: Spec, seed_a: int, seed_b: int) -> None:
    assert decision(_render(spec, seed_a)) == decision(_render(spec, seed_b))


def check_alias_rename_keeps_lineage(spec: Spec, seed: int) -> None:
    first = validate_mysql(_render(spec, seed, alias_style=0))
    second = validate_mysql(_render(spec, seed, alias_style=1))
    plan = [(o.kind, o.source, o.protected) for o in first.outputs]
    assert plan == [(o.kind, o.source, o.protected) for o in second.outputs]
    assert first.parameters == second.parameters


def check_generated_sql_reparses_and_validates(spec: Spec, seed: int) -> None:
    query = validate_mysql(_render(spec, seed))
    reparsed = parse_select(
        query.sql.replace("%%", "%").replace("%s", "'x'"),
        ParserLimits.from_runtime(RUNTIME),
        MYSQL,
    )
    validate_allowlist(reparsed)
    assert not list(reparsed.find_all(exp.Placeholder))
    assert PREFIX not in query.sql


def check_generated_sql_is_a_fixpoint(spec: Spec, seed: int) -> None:
    first = validate_mysql(_render(spec, seed))
    # The driver applies %-formatting: undo the %% escape before reading the SQL back.
    restored = with_tokens(first.sql, first.parameters, "%s").replace("%%", "%")
    second = validate_mysql(restored)
    assert (second.sql, second.parameters) == (first.sql, first.parameters)


def backtick(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def check_quoted_aliases_round_trip(column_alias: str, table_alias: str) -> None:
    sql = (
        f"SELECT {backtick(table_alias)}.id AS {backtick(column_alias)} "
        f"FROM users AS {backtick(table_alias)}"
    )
    try:
        query = validate_mysql(sql)
    except DomainError as error:
        assert error.code is ErrorCode.QUERY_REJECTED
        return
    assert parse_one(query.sql.replace("%%", "%"), dialect="mysql") == query.ast


def _lineage(query: ValidatedQuery) -> list[tuple[Any, ...]]:
    return [
        (
            output.kind,
            None
            if output.source is None
            else (output.source.table.casefold(), output.source.column.casefold()),
            output.protected,
        )
        for output in query.outputs
    ]


def check_dialects_agree_on_lineage(spec: Spec, seed: int) -> None:
    """The same restricted query has the same lineage and protection on both dialects."""
    tsql = validate(render(spec, seed))
    mysql = validate_mysql(_render(spec, seed))
    assert _lineage(tsql) == _lineage(mysql)
    assert len(tsql.parameters) == len(mysql.parameters)


# Constructs both dialects parse; each must be rejected for the same reason on both.
SHARED_FORBIDDEN_MUTATIONS: list[Callable[[str], str]] = [
    lambda s: s + " UNION SELECT 1",
    lambda s: s + "; DROP TABLE Canary",
    lambda s: _sub(_SELECT_KW, "SELECT DISTINCT", s),
    lambda s: _sub(_SELECT_KW, "SELECT (SELECT 1),", s),
    lambda s: _sub(_SELECT_KW, "SELECT CASE WHEN 1 = 1 THEN 1 END,", s),
    lambda s: _sub(_SELECT_KW, "WITH c AS (SELECT 1 AS n) SELECT", s),
    lambda s: _sub(_SELECT_KW, "SELECT SUM(u.Id),", s),
    lambda s: _sub(_FROM_KW, "FROM Users x, ", s),
]


def _rejection(run: Callable[[str], object], sql: str) -> str:
    try:
        run(sql)
    except DomainError as error:
        assert error.code is ErrorCode.QUERY_REJECTED, (sql, error)
        return error.public_message
    raise AssertionError(f"accepted forbidden construct: {sql!r}")


def check_dialects_reject_for_the_same_reason(spec: Spec, seed: int, mutation_index: int) -> None:
    mutate = SHARED_FORBIDDEN_MUTATIONS[mutation_index % len(SHARED_FORBIDDEN_MUTATIONS)]
    # Without TOP: a mutation inserted after SELECT would otherwise land before T-SQL's TOP.
    spec = replace(spec, top=None)
    tsql = _rejection(validate, mutate(render(spec, seed)))
    mysql = _rejection(validate_mysql, mutate(_render(spec, seed)))
    assert tsql == mysql, (tsql, mysql)


def check_every_forbidden_mutation_changes_the_query(spec: Spec, seed: int) -> None:
    sql = _render(spec, seed)
    for index, mutate in enumerate(MYSQL_FORBIDDEN_MUTATIONS):
        assert mutate(sql) != sql, f"mutation {index} is a no-op for {sql!r}"


def check_forbidden_constructs_are_rejected_and_never_executed(
    spec: Spec, seed: int, mutation_index: int
) -> None:
    sql = _render(spec, seed)
    mutated = MYSQL_FORBIDDEN_MUTATIONS[mutation_index % len(MYSQL_FORBIDDEN_MUTATIONS)](sql)
    assert mutated != sql, "mutation did not change the query"
    before = len(SPY.calls)
    try:
        asyncio.run(SERVICE.execute_sql(ALIAS, DATABASE, mutated))
    except DomainError as error:
        assert error.code is ErrorCode.QUERY_REJECTED, (mutated, error)
    else:
        raise AssertionError(f"accepted forbidden construct: {mutated!r}")
    assert len(SPY.calls) == before


def check_only_validated_sql_is_ever_executed(text: str) -> None:
    before = len(SPY.calls)
    with contextlib.suppress(DomainError):
        asyncio.run(SERVICE.execute_sql(ALIAS, DATABASE, text))
    executed = SPY.calls[before:]
    assert len(executed) <= 1
    for statement, parameters in executed:
        validated = validate_mysql(text)
        assert (statement, parameters) == (validated.sql, validated.parameters)


def check_sql_looking_values_stay_binds(value: str) -> None:
    token = OWN.encrypt(value)
    query = validate_mysql(f"SELECT u.Id FROM Users u WHERE u.Email = '{token}'")
    assert query.parameters == (value,)
    static = validate_mysql(
        "SELECT u.Id FROM Users u WHERE u.Email = '" + str(OWN.encrypt("x")) + "'"
    )
    assert query.sql == static.sql
    assert token not in query.sql
