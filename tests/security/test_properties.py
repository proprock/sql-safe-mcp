"""Hypothesis properties, security-fast profile (deterministic, ~200 examples each)."""

from __future__ import annotations

import property_checks as checks
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlglot import exp
from support import RUNTIME, Spec, render, specs
from test_allowlist import ALLOWED

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.parser import (
    _ALLOWED_ARGS,
    ParserLimits,
    parse_select,
    validate_allowlist,
)

LIMITS = ParserLimits.from_runtime(RUNTIME)
SEEDS = st.integers(0, 2**32 - 1)
ALIAS_NAMES = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789._-", min_size=1, max_size=12)
SQL_FRAGMENTS = st.lists(
    st.sampled_from(
        [
            "SELECT",
            "FROM",
            "Users",
            "u",
            "WHERE",
            "Email",
            "=",
            "IN",
            "(",
            ")",
            "'",
            "--",
            ";",
            "/*",
            "*/",
            "UNION",
            "JOIN",
            "ON",
            "1",
            "NULL",
            "*",
            ",",
            "TOP",
            "ORDER BY",
            "[",
            "]",
            "pii:v1:",
            "dbo",
            ".",
            "@x",
            "#t",
            "EXEC",
            "DROP TABLE",
            "WITH",
            "AS",
            "NOT",
            "\x00",
        ]
    ),
    max_size=30,
).map(" ".join)


@given(specs(), SEEDS)
def test_valid_specs_are_accepted(spec: Spec, seed: int) -> None:
    checks.check_valid_specs_are_accepted(spec, seed)


@given(specs(), SEEDS, SEEDS)
def test_formatting_does_not_change_the_decision(spec: Spec, a: int, b: int) -> None:
    checks.check_formatting_does_not_change_the_decision(spec, a, b)


@given(specs(), SEEDS)
def test_alias_rename_keeps_lineage(spec: Spec, seed: int) -> None:
    checks.check_alias_rename_keeps_lineage(spec, seed)


@given(specs(), SEEDS)
def test_generated_sql_reparses_and_validates(spec: Spec, seed: int) -> None:
    checks.check_generated_sql_reparses_and_validates(spec, seed)


@given(specs(), SEEDS)
def test_generated_sql_is_a_fixpoint(spec: Spec, seed: int) -> None:
    checks.check_generated_sql_is_a_fixpoint(spec, seed)


QUOTED_NAMES = st.text(alphabet=checks.QUOTING_ALPHABET, min_size=1, max_size=12)


@given(QUOTED_NAMES, QUOTED_NAMES)
def test_quoted_aliases_round_trip(column_alias: str, table_alias: str) -> None:
    checks.check_quoted_aliases_round_trip(column_alias, table_alias)


@given(specs(), SEEDS)
def test_every_forbidden_mutation_actually_changes_the_query(spec: Spec, seed: int) -> None:
    checks.check_every_forbidden_mutation_changes_the_query(spec, seed)


@given(specs(), SEEDS, st.integers(0, 10_000))
def test_forbidden_constructs_are_rejected_and_never_executed(
    spec: Spec, seed: int, mutation: int
) -> None:
    checks.check_forbidden_constructs_are_rejected_and_never_executed(spec, seed, mutation)


@given(st.one_of(st.text(max_size=200), SQL_FRAGMENTS))
def test_only_validated_sql_is_ever_executed(text: str) -> None:
    checks.check_only_validated_sql_is_ever_executed(text)


@given(st.lists(st.text(alphabet="ÀÉÎÕÜßøæ ", min_size=4, max_size=30), min_size=1, max_size=5))
def test_plaintext_is_never_serialized(values: list[str]) -> None:
    checks.check_plaintext_is_never_serialized(values)


@given(st.text(max_size=40), ALIAS_NAMES, ALIAS_NAMES)
def test_token_belongs_to_its_alias(value: str, a: str, b: str) -> None:
    checks.check_token_belongs_to_its_alias(value, a, b)


@given(st.text(max_size=40), st.integers(0, 10_000), st.characters(codec="ascii"))
def test_tampered_token_is_rejected(value: str, position: int, replacement: str) -> None:
    checks.check_tampered_token_is_rejected(value, position, replacement)


@given(st.one_of(st.text(max_size=300), st.binary(max_size=200).map(lambda b: b.hex())))
def test_arbitrary_token_input_only_raises_the_public_error(text: str) -> None:
    checks.check_arbitrary_token_input_only_raises_the_public_error(text)


@given(
    st.one_of(
        st.text(max_size=60),
        st.sampled_from(["x'; DROP TABLE Canary;--", "' OR '1'='1", "'); EXEC xp_cmdshell 'x';--"]),
    )
)
def test_sql_looking_values_stay_binds(value: str) -> None:
    checks.check_sql_looking_values_stay_binds(value)


ALLOWED_KINDS = sorted(_ALLOWED_ARGS, key=lambda cls: cls.__name__)


@pytest.mark.parametrize("parent", ALLOWED_KINDS, ids=lambda cls: cls.__name__)
def test_every_allowed_node_is_rejected_in_an_unlisted_position(parent: type[exp.Expr]) -> None:
    for kind in ALLOWED_KINDS:
        checks.check_node_position_is_allowlisted(kind, parent)


def _observed_parent_pairs(sqls: list[str]) -> set[tuple[type[exp.Expr], type]]:
    pairs = set()
    for sql in sqls:
        for node in parse_select(sql, LIMITS).walk():
            if node.parent is not None:
                pairs.add((type(node), type(node.parent)))
    return pairs


def test_parent_table_is_exactly_what_accepted_queries_use() -> None:
    sqls = list(ALLOWED.values())
    examples = 0

    @settings(max_examples=500, deadline=None, derandomize=True)
    @given(specs(), SEEDS)
    def collect(spec: Spec, seed: int) -> None:
        nonlocal examples
        examples += 1
        sqls.append(render(spec, seed))

    collect()
    assert examples >= 500
    observed = _observed_parent_pairs(sqls)
    assert observed == checks.allowed_parent_pairs()


@pytest.mark.parametrize("parent", ALLOWED_KINDS, ids=lambda cls: cls.__name__)
def test_placeholders_are_accepted_only_as_comparison_and_in_operands(
    parent: type[exp.Expr],
) -> None:
    listed = parent in {exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE, exp.In}
    for slot in ("this", "expression", "expressions"):
        if slot not in _ALLOWED_ARGS[parent]:
            continue
        holder = checks.instance(parent)
        holder.set(
            slot,
            [exp.Placeholder(this="p")] if slot == "expressions" else exp.Placeholder(this="p"),
        )
        for query in checks._placements(holder):
            try:
                validate_allowlist(query, allow_placeholders=True)
            except DomainError as error:
                assert error.code is ErrorCode.QUERY_REJECTED
            else:
                assert listed, f"Placeholder accepted in {parent.__name__}.{slot}"


def _all_expression_classes() -> list[type[exp.Expr]]:
    found: dict[str, type[exp.Expr]] = {}
    pending: list[type[exp.Expr]] = [exp.Expr]
    while pending:
        for cls in pending.pop().__subclasses__():
            if cls.__name__ not in found:
                found[cls.__name__] = cls
                pending.append(cls)
    return [found[name] for name in sorted(found)]


UNKNOWN_NODES = [cls for cls in _all_expression_classes() if cls not in _ALLOWED_ARGS]


def _assert_rejected(query: exp.Select) -> None:
    with pytest.raises(DomainError) as info:
        validate_allowlist(query)
    assert info.value.code is ErrorCode.QUERY_REJECTED


def _in_where(node: exp.Expr) -> exp.Select:
    query = exp.select("Id").from_("Users")
    query.set("where", exp.Where(this=node))
    return query


def _in_projection(node: exp.Expr) -> exp.Select:
    query = exp.select("Id").from_("Users")
    query.set("expressions", [node])
    return query


def test_unlisted_node_universe_is_large_and_includes_the_dangerous_ones() -> None:
    names = {cls.__name__ for cls in UNKNOWN_NODES}
    assert len(UNKNOWN_NODES) > 500
    assert {"Anonymous", "Subquery", "Union", "Cast", "Case", "Window", "Pivot", "Lateral"} <= names


@pytest.mark.parametrize("cls", UNKNOWN_NODES, ids=lambda cls: cls.__name__)
def test_every_unlisted_sqlglot_node_is_rejected(cls: type[exp.Expr]) -> None:
    """Unknown defaults reject: no node type outside the allowlist may pass, in any position."""
    if cls is exp.Placeholder:
        pytest.skip("placeholders are admitted only after the token rewrite")
    _assert_rejected(_in_where(cls()))
    _assert_rejected(_in_projection(cls()))


def _column(name: str = "Id") -> exp.Column:
    return exp.column(name, table="u")


_SELECT_ONE = exp.select("1")
EXPLICIT_DANGEROUS: dict[str, exp.Expr] = {
    "anonymous function": exp.Anonymous(this="F", expressions=[_column()]),
    "scalar subquery": exp.Subquery(this=_SELECT_ONE.copy()),
    "union": exp.Union(this=_SELECT_ONE.copy(), expression=_SELECT_ONE.copy(), distinct=False),
    "intersect": exp.Intersect(this=_SELECT_ONE.copy(), expression=_SELECT_ONE.copy()),
    "except": exp.Except(this=_SELECT_ONE.copy(), expression=_SELECT_ONE.copy()),
    "exists": exp.Exists(this=_SELECT_ONE.copy()),
    "in subquery": exp.In(this=_column(), query=_SELECT_ONE.copy()),
    "cast": exp.Cast(this=_column(), to=exp.DataType.build("varchar")),
    "case": exp.Case(ifs=[exp.If(this=exp.true(), true=exp.Literal.number(1))]),
    "window": exp.Window(
        this=exp.RowNumber(), order=exp.Order(expressions=[exp.Ordered(this=_column())])
    ),
    "sum": exp.Sum(this=_column()),
    "count column": exp.Count(this=_column()),
    "count distinct": exp.Count(this=exp.Distinct(expressions=[_column()])),
    "lower": exp.Lower(this=_column()),
    "concat": exp.Concat(expressions=[_column(), _column()]),
    "add": exp.Add(this=_column(), expression=exp.Literal.number(1)),
    "like": exp.Like(this=_column(), expression=exp.Literal.string("a%")),
    "between": exp.Between(this=_column(), low=exp.Literal.number(1), high=exp.Literal.number(2)),
    "not": exp.Not(this=exp.EQ(this=_column(), expression=exp.Literal.number(1))),
    "parameter": exp.Parameter(this=exp.Var(this="x")),
    "variable": exp.Var(this="x"),
    "hint table": exp.Table(
        this=exp.to_identifier("Users"),
        hints=[exp.WithTableHint(expressions=[exp.Var(this="NOLOCK")])],
    ),
    "temp identifier table": exp.Table(this=exp.to_identifier("#t")),
    "table with catalog": exp.Table(
        this=exp.to_identifier("t"), db=exp.to_identifier("d"), catalog=exp.to_identifier("c")
    ),
    "distinct": exp.Distinct(expressions=[_column()]),
    "star comparison": exp.EQ(this=exp.Star(), expression=exp.Literal.number(1)),
    "is with non null": exp.Is(this=_column(), expression=exp.Literal.number(1)),
    "in with column item": exp.In(this=_column(), expressions=[_column()]),
    "neg of column": exp.Neg(this=_column()),
    "order by expression": exp.Ordered(
        this=exp.Add(this=_column(), expression=exp.Literal.number(1))
    ),
}


@pytest.mark.parametrize("node", EXPLICIT_DANGEROUS.values(), ids=EXPLICIT_DANGEROUS.keys())
def test_explicit_dangerous_nodes_are_rejected_in_every_position(node: exp.Expr) -> None:
    _assert_rejected(_in_where(node.copy()))
    _assert_rejected(_in_projection(node.copy()))


@pytest.mark.parametrize(
    ("arg", "value"),
    [
        ("distinct", exp.Distinct()),
        ("group", exp.Group(expressions=[_column()])),
        ("having", exp.Having(this=exp.true())),
        ("with_", exp.With(expressions=[])),
        ("into", exp.Into(this=exp.to_table("t"))),
        ("offset", exp.Offset(expression=exp.Literal.number(1))),
        ("locks", [exp.Lock(update=True)]),
        ("options", [exp.QueryOption(this=exp.Var(this="RECOMPILE"))]),
        ("kind", "STRUCT"),
        ("hint", exp.Hint(expressions=[])),
    ],
)
def test_every_select_option_outside_the_allowlist_is_rejected(arg: str, value: object) -> None:
    query = exp.select("Id").from_("Users")
    query.set(arg, value)
    _assert_rejected(query)


def test_dangerous_node_types_are_not_allowlisted() -> None:
    assert exp.Anonymous not in _ALLOWED_ARGS
    assert exp.Subquery not in _ALLOWED_ARGS
    assert exp.Union not in _ALLOWED_ARGS
