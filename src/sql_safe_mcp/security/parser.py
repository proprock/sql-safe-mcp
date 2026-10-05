from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp

from sql_safe_mcp.config import RuntimeConfig
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import SQLSERVER, SqlDialect
from sql_safe_mcp.security.reasons import Reason


@dataclass(frozen=True, slots=True)
class ParserLimits:
    max_sql_chars: int
    max_ast_nodes: int
    max_joins: int
    max_in_list_items: int

    @classmethod
    def from_runtime(cls, runtime: RuntimeConfig) -> ParserLimits:
        return cls(
            runtime.max_sql_chars,
            runtime.max_ast_nodes,
            runtime.max_joins,
            runtime.max_in_list_items,
        )


REJECT_HINT = "Rewrite the operation as a single, simpler SELECT query."


def reject(reason: Reason, detail: str | None = None) -> DomainError:
    """Build the QUERY_REJECTED error; only a fixed Reason (plus an optional name) is accepted."""
    if not isinstance(reason, Reason):
        raise TypeError("reject() takes a Reason")
    text = str(reason) if detail is None else f"{reason}: {detail}"
    return DomainError(ErrorCode.QUERY_REJECTED, f"Query rejected: {text}.", REJECT_HINT)


def check_limits(query: exp.Expression, limits: ParserLimits) -> None:
    """Enforce AST size limits; also used again after transformations."""
    for count, _ in enumerate(query.walk(), start=1):
        if count > limits.max_ast_nodes:
            raise reject(Reason.LIMIT_NODES)
    if sum(1 for _ in query.find_all(exp.Join)) > limits.max_joins:
        raise reject(Reason.LIMIT_JOINS)
    for node in query.find_all(exp.In):
        if len(node.expressions) > limits.max_in_list_items:
            raise reject(Reason.LIMIT_IN_LIST)


_COMPARISONS = (exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE)

# node type -> argument names that may be non-empty; everything else is rejected.
_ALLOWED_ARGS: dict[type[exp.Expr], frozenset[str]] = {
    exp.Select: frozenset({"expressions", "from_", "joins", "where", "order", "limit"}),
    exp.From: frozenset({"this"}),
    exp.Table: frozenset({"this", "db", "alias"}),
    exp.TableAlias: frozenset({"this"}),
    exp.Identifier: frozenset({"this", "quoted"}),
    exp.Column: frozenset({"this", "table"}),
    exp.Star: frozenset(),
    exp.Count: frozenset({"this", "big_int"}),  # big_int: a flag the mysql parser sets
    exp.Literal: frozenset({"this", "is_string"}),
    exp.Null: frozenset(),
    exp.Neg: frozenset({"this"}),
    exp.Alias: frozenset({"this", "alias"}),
    exp.Join: frozenset({"this", "on", "side", "kind"}),
    exp.And: frozenset({"this", "expression"}),
    exp.Or: frozenset({"this", "expression"}),
    exp.Paren: frozenset({"this"}),
    exp.In: frozenset({"this", "expressions"}),
    exp.Is: frozenset({"this", "expression"}),
    exp.Where: frozenset({"this"}),
    exp.Order: frozenset({"expressions"}),
    exp.Ordered: frozenset({"this", "desc", "nulls_first"}),
    exp.Limit: frozenset({"expression"}),
    **{comparison: frozenset({"this", "expression"}) for comparison in _COMPARISONS},
}
_PLACEHOLDER_ARGS = frozenset({"this"})
# What an alias may name: a direct column, a literal, or COUNT(*). Anything else (a Paren, a
# comparison, ...) would be invisible to lineage and could project a protected column in clear.
# A Star under an alias is still rejected by the Star branch below with its own reason.
_ALIASED = (exp.Column, exp.Star, exp.Literal, exp.Null, exp.Neg, exp.Count)
_PROJECTIONS = (exp.Column, exp.Star, exp.Literal, exp.Null, exp.Neg, exp.Alias, exp.Count)


def _is_numeric_literal(node: object) -> bool:
    return isinstance(node, exp.Literal) and not node.is_string


def _is_empty(value: object) -> bool:
    return value is None or value is False or value == []


def _check_node(node: exp.Expr, allow_placeholders: bool) -> None:
    kind = type(node)
    if kind is exp.Placeholder and allow_placeholders:
        allowed_args = _PLACEHOLDER_ARGS
    elif kind in _ALLOWED_ARGS:
        allowed_args = _ALLOWED_ARGS[kind]
    else:
        raise reject(Reason.NODE_UNSUPPORTED, kind.__name__)
    for name, value in node.args.items():
        if name not in allowed_args and not _is_empty(value):
            raise reject(Reason.OPTION_UNSUPPORTED, f"{kind.__name__}.{name}")

    if isinstance(node, exp.Table):
        name = node.this
        if not isinstance(name, exp.Identifier) or str(name.this).startswith(("#", "@")):
            raise reject(Reason.TABLE_UNSUPPORTED)
    elif isinstance(node, exp.Column):
        if not isinstance(node.this, (exp.Identifier, exp.Star)):
            raise reject(Reason.COLUMN_REFERENCE_UNSUPPORTED)
    elif isinstance(node, exp.Alias):
        if not isinstance(node.this, _ALIASED):
            raise reject(Reason.PROJECTION_UNSUPPORTED)
    elif isinstance(node, exp.Count):
        if not isinstance(node.this, exp.Star):
            raise reject(Reason.COUNT_STAR_ONLY)
    elif isinstance(node, exp.Star):
        if not isinstance(node.parent, (exp.Select, exp.Column, exp.Count)):
            raise reject(Reason.STAR_PROJECTION_ONLY)
    elif isinstance(node, exp.Join):
        if not isinstance(node.this, exp.Table) or node.args.get("on") is None:
            raise reject(Reason.JOIN_NEEDS_ON)
        if node.side not in {"", "LEFT"} or node.kind not in {"", "INNER"}:
            raise reject(Reason.JOIN_TYPE_UNSUPPORTED)
    elif isinstance(node, exp.Is):
        if not isinstance(node.expression, exp.Null):
            raise reject(Reason.IS_NULL_ONLY)
    elif isinstance(node, exp.Neg):
        if not _is_numeric_literal(node.this):
            raise reject(Reason.NEGATION_NUMERIC_ONLY)
    elif isinstance(node, exp.Limit):
        value = node.expression
        if not _is_numeric_literal(value) or not str(value.this).isdigit():
            raise reject(Reason.TOP_INTEGER_ONLY)
    elif isinstance(node, exp.Ordered):
        if not isinstance(node.this, exp.Column) or isinstance(node.this.this, exp.Star):
            raise reject(Reason.ORDER_DIRECT_COLUMNS_ONLY)
    elif isinstance(node, exp.In):
        if not isinstance(node.this, exp.Column) or not all(
            isinstance(item, (exp.Literal, exp.Neg, exp.Placeholder)) for item in node.expressions
        ):
            raise reject(Reason.IN_LITERALS_ONLY)
    elif isinstance(node, _COMPARISONS):
        for side in (node.this, node.expression):
            if isinstance(side, exp.Star):
                raise reject(Reason.STAR_COMPARISON)


def validate_allowlist(query: exp.Expression, *, allow_placeholders: bool = False) -> None:
    """Fail closed on any node type, argument, or shape outside the supported subset."""
    if not isinstance(query, exp.Select):
        raise reject(Reason.SELECT_ONLY)
    for node in query.walk():
        _check_node(node, allow_placeholders)
    for projection in query.expressions:
        if not isinstance(projection, _PROJECTIONS):
            raise reject(Reason.PROJECTION_UNSUPPORTED)


def strip_comments(query: exp.Expression) -> None:
    """Drop caller comments so no caller-controlled text is ever emitted into generated SQL."""
    for node in query.walk():
        node.pop_comments()


def parse_select(sql: str, limits: ParserLimits, dialect: SqlDialect = SQLSERVER) -> exp.Select:
    """Parse exactly one root SELECT; any failure becomes QUERY_REJECTED."""
    if len(sql) > limits.max_sql_chars:
        raise reject(Reason.LIMIT_CHARS)
    try:
        statements = [s for s in sqlglot.parse(sql, dialect=dialect.name) if s is not None]
        if len(statements) != 1:
            raise reject(Reason.ONE_STATEMENT)
        query = statements[0]
        if not isinstance(query, exp.Select):
            raise reject(Reason.SELECT_ONLY)
        check_limits(query, limits)
        validate_allowlist(query)
        strip_comments(query)
    except DomainError:
        raise
    except Exception as exc:
        raise reject(Reason.PARSE_FAILED) from exc
    return query
