"""Property bodies shared by the fast and deep Hypothesis suites.

Any minimized failing example found by these properties must be added to tests/security/corpus.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

from sqlglot import exp
from support import (
    ALIAS,
    DATABASE,
    FORBIDDEN_MUTATIONS,
    KEY,
    OTHER_KEY,
    OWN,
    RUNTIME,
    Spec,
    SpyConnection,
    SpyResult,
    render,
    spy_service,
    validate,
)

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.models import SqlResult
from sql_safe_mcp.security.executor import execute_validated
from sql_safe_mcp.security.parser import (
    _ALLOWED_ARGS,
    _ALLOWED_PARENTS,
    ParserLimits,
    parse_select,
    validate_allowlist,
)
from sql_safe_mcp.security.tokens import PREFIX, TokenCodec

SPY = SpyConnection()
SERVICE = spy_service(SPY)


def decision(sql: str) -> tuple[Any, ...]:
    query = validate(sql)
    outputs = tuple((o.label, o.kind, o.source, o.protected) for o in query.outputs)
    return query.sql, query.parameters, outputs


def check_valid_specs_are_accepted(spec: Spec, seed: int) -> None:
    """Every generated restricted query is accepted (no over-rejection) and bounded."""
    query = validate(render(spec, seed))
    assert query.sql.upper().startswith("SELECT TOP ")
    assert query.sql.count("?") == len(query.parameters)


def check_formatting_does_not_change_the_decision(spec: Spec, seed_a: int, seed_b: int) -> None:
    assert decision(render(spec, seed_a)) == decision(render(spec, seed_b))


def check_alias_rename_keeps_lineage(spec: Spec, seed: int) -> None:
    first = validate(render(spec, seed, alias_style=0))
    second = validate(render(spec, seed, alias_style=1))
    plan = [(o.kind, o.source, o.protected) for o in first.outputs]
    assert plan == [(o.kind, o.source, o.protected) for o in second.outputs]
    assert first.parameters == second.parameters


def check_generated_sql_reparses_and_validates(spec: Spec, seed: int) -> None:
    query = validate(render(spec, seed))
    reparsed = parse_select(
        query.sql.replace("?", "'x'"),
        ParserLimits.from_runtime(RUNTIME),
    )
    validate_allowlist(reparsed)
    assert not list(reparsed.find_all(exp.Placeholder))
    assert PREFIX not in query.sql


def check_every_forbidden_mutation_changes_the_query(spec: Spec, seed: int) -> None:
    """Guards the guard: a mutation that silently does nothing would inflate the coverage."""
    sql = render(spec, seed)
    for index, mutate in enumerate(FORBIDDEN_MUTATIONS):
        assert mutate(sql) != sql, f"mutation {index} is a no-op for {sql!r}"


def check_forbidden_constructs_are_rejected_and_never_executed(
    spec: Spec, seed: int, mutation_index: int
) -> None:
    sql = render(spec, seed, alias_style=0)
    mutated = FORBIDDEN_MUTATIONS[mutation_index % len(FORBIDDEN_MUTATIONS)](sql)
    assert mutated != sql, "mutation did not change the query"
    before = len(SPY.calls)
    try:
        asyncio.run(SERVICE.execute_sql(ALIAS, DATABASE, mutated))
    except DomainError as error:
        assert error.code is ErrorCode.QUERY_REJECTED, (mutated, error)
    else:
        raise AssertionError(f"accepted forbidden construct: {mutated!r}")
    assert len(SPY.calls) == before


_SLOTS = (
    "this",
    "expression",
    "expressions",
    "alias",
    "table",
    "db",
    "on",
    "where",
    "from_",
    "joins",
    "order",
    "limit",
)
_LIST_SLOTS = frozenset({"expressions", "joins"})


def _placements(parent: exp.Expr) -> list[exp.Select]:
    """Minimal SELECTs holding `parent` in every clause that could legally host it."""
    table = exp.to_table("t")
    wrappers = {
        "raw expressions": lambda q: q.set("expressions", [parent.copy()]),
        "raw where": lambda q: q.set("where", parent.copy()),
        "raw from": lambda q: q.set("from_", parent.copy()),
        "raw joins": lambda q: q.set("joins", [parent.copy()]),
        "raw order": lambda q: q.set("order", parent.copy()),
        "raw limit": lambda q: q.set("limit", parent.copy()),
        "where": lambda q: q.set("where", exp.Where(this=parent.copy())),
        "from": lambda q: q.set("from_", exp.From(this=parent.copy())),
        "join on": lambda q: q.set("joins", [exp.Join(this=table.copy(), on=parent.copy())]),
        "join": lambda q: q.set("joins", [exp.Join(this=parent.copy(), on=exp.true())]),
        "order": lambda q: q.set("order", exp.Order(expressions=[parent.copy()])),
        "limit": lambda q: q.set("limit", exp.Limit(expression=parent.copy())),
    }
    queries = []
    for place in wrappers.values():
        query = exp.select("Id").from_("Users")
        place(query)
        queries.append(query)
    return queries


def _slot_queries(kind: type[exp.Expr], parent: type[exp.Expr], slot: str) -> list[exp.Select]:
    holder = instance(parent)
    holder.set(slot, [instance(kind)] if slot in _LIST_SLOTS else instance(kind))
    return _placements(holder)


def instance(kind: type[exp.Expr]) -> exp.Expr:
    """An empty node of `kind`; a Literal needs its is_string flag like every parsed one."""
    return exp.Literal.number(1) if kind is exp.Literal else kind()


def allowed_parent_pairs() -> set[tuple[type[exp.Expr], type[exp.Expr]]]:
    """(kind, parent) pairs the position allowlist admits, with the root as `exp.Select` itself."""
    return {
        (kind, parent)
        for kind, parents in _ALLOWED_PARENTS.items()
        for parent in parents
        if parent is not None
    }


def check_node_position_is_allowlisted(kind: type[exp.Expr], parent: type[exp.Expr]) -> None:
    """An allowed node type under a parent outside _ALLOWED_PARENTS is rejected, never a crash."""
    listed = (kind, parent) in allowed_parent_pairs()
    if parent is exp.Literal:
        return  # a Literal holds a string, never a child node
    for slot in _SLOTS:
        if slot not in _ALLOWED_ARGS[parent]:
            continue
        for query in _slot_queries(kind, parent, slot):
            try:
                validate_allowlist(query)
            except DomainError as error:
                assert error.code is ErrorCode.QUERY_REJECTED, (kind, parent, slot, error)
            else:
                assert listed, f"{kind.__name__} accepted in {parent.__name__}.{slot}"


def check_only_validated_sql_is_ever_executed(text: str) -> None:
    """Anything that reached the driver is exactly what the validator produces for that text."""
    before = len(SPY.calls)
    with contextlib.suppress(DomainError):
        asyncio.run(SERVICE.execute_sql(ALIAS, DATABASE, text))
    executed = SPY.calls[before:]
    assert len(executed) <= 1
    for statement, parameters in executed:
        validated = validate(text)
        assert (statement, parameters) == (validated.sql, validated.parameters)


def check_plaintext_is_never_serialized(values: list[str]) -> None:
    connection = SpyConnection(SpyResult(["Email"], [(value,) for value in values]))
    query = validate("SELECT u.Email FROM Users u")
    result = execute_validated(connection, query, OWN)
    api = SqlResult(
        columns=[
            {"name": c.name, "source": None, "protected": c.protected, "encoding": c.encoding}
            for c in result.columns
        ],
        rows=[list(row) for row in result.rows],
        row_count=len(result.rows),
        truncated=result.truncated,
    )
    serialized = json.dumps(result.rows) + repr(result) + api.model_dump_json()
    for value in values:
        if len(value) >= 4:
            assert value not in serialized
    assert [OWN.decrypt(row[0]) for row in result.rows] == values


def check_token_belongs_to_its_alias(value: str, alias_a: str, alias_b: str) -> None:
    issuer = TokenCodec(alias_a, KEY)
    other = TokenCodec(alias_b, KEY)
    token = issuer.encrypt(value)
    assert issuer.decrypt(token) == value
    if alias_a != alias_b:
        try:
            other.decrypt(token)
        except DomainError as error:
            assert error.code is ErrorCode.INVALID_PII_TOKEN
        else:
            raise AssertionError("token accepted under another alias")
    try:
        TokenCodec(alias_a, OTHER_KEY).decrypt(token)
    except DomainError as error:
        assert error.code is ErrorCode.INVALID_PII_TOKEN
    else:
        raise AssertionError("token accepted under another key")


def check_tampered_token_is_rejected(value: str, position: int, replacement: str) -> None:
    token = OWN.encrypt(value)
    body_start = len(PREFIX)
    index = body_start + position % (len(token) - body_start)
    if token[index] == replacement:
        return
    tampered = token[:index] + replacement + token[index + 1 :]
    try:
        OWN.decrypt(tampered)
    except DomainError as error:
        assert error.code is ErrorCode.INVALID_PII_TOKEN
    else:
        raise AssertionError("tampered token accepted")


def check_arbitrary_token_input_only_raises_the_public_error(text: str) -> None:
    for candidate in (text, PREFIX + text):
        try:
            OWN.decrypt(candidate)
        except DomainError as error:
            assert error.code is ErrorCode.INVALID_PII_TOKEN
        else:
            raise AssertionError("arbitrary input decrypted")


def check_sql_looking_values_stay_binds(value: str) -> None:
    token = OWN.encrypt(value)
    query = validate(f"SELECT u.Id FROM Users u WHERE u.Email = '{token}'")
    assert query.parameters == (value,)
    static = validate("SELECT u.Id FROM Users u WHERE u.Email = '" + str(OWN.encrypt("x")) + "'")
    assert query.sql == static.sql
    assert token not in query.sql
