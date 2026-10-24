from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any, Literal, NoReturn

from sqlglot import exp

from sql_safe_mcp.config import RuntimeConfig
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.dialect import SQLSERVER, SqlDialect
from sql_safe_mcp.security.lineage import AnalyzedQuery, SourceColumn
from sql_safe_mcp.security.parser import (
    ParserLimits,
    check_limits,
    reject,
    validate_allowlist,
)
from sql_safe_mcp.security.policy import PolicyDecision
from sql_safe_mcp.security.reasons import Reason
from sql_safe_mcp.security.tokens import PREFIX

_SEAL = object()


@dataclass(frozen=True, slots=True)
class OutputPlan:
    label: str
    kind: Literal["column", "count", "literal"]
    source: SourceColumn | None
    protected: bool
    domain: str | None = None


class ValidatedQuery:
    """SQL produced by the validation pipeline; the only input the executor accepts.

    `sql` uses the dialect bind markers (`?` or `%s`) and `parameters` holds the matching decrypted
    values, so no bind value is ever part of the statement text.

    Instances are issued by `issue_validated_query` after the final AST check. There is no public
    constructor, and the object cannot be copied or serialized. `repr` never shows SQL or binds.
    """

    __slots__ = (
        "_alias",
        "_ast",
        "_database",
        "_max_rows",
        "_outputs",
        "_parameters",
        "_references",
        "_sql",
        "_tables",
    )

    def __init__(
        self,
        seal: object,
        *,
        alias: str,
        database: str,
        ast: exp.Select,
        sql: str,
        parameters: tuple[Any, ...],
        outputs: tuple[OutputPlan, ...],
        max_rows: int,
        references: tuple[SourceColumn, ...] = (),
        tables: tuple[tuple[str, str], ...] = (),
    ) -> None:
        if seal is not _SEAL:
            raise TypeError("ValidatedQuery can only be issued by the validation pipeline")
        object.__setattr__(self, "_alias", alias)
        object.__setattr__(self, "_database", database)
        object.__setattr__(self, "_ast", ast)
        object.__setattr__(self, "_sql", sql)
        object.__setattr__(self, "_parameters", tuple(parameters))
        object.__setattr__(self, "_outputs", outputs)
        object.__setattr__(self, "_references", references)
        object.__setattr__(self, "_tables", tables)
        object.__setattr__(self, "_max_rows", max_rows)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("ValidatedQuery is read-only")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ValidatedQuery is read-only")

    def __copy__(self) -> NoReturn:
        raise TypeError("ValidatedQuery cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("ValidatedQuery cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ValidatedQuery cannot be serialized")

    def __repr__(self) -> str:
        return (
            f"ValidatedQuery(alias={self._alias!r}, database={self._database!r}, "
            f"outputs={len(self._outputs)}, parameters={len(self._parameters)})"
        )

    @property
    def alias(self) -> str:
        return self._alias

    @property
    def database(self) -> str:
        return self._database

    @property
    def sql(self) -> str:
        return self._sql

    @property
    def parameters(self) -> tuple[Any, ...]:
        """Bind values in the order of the bind markers in `sql`."""
        return self._parameters

    @property
    def outputs(self) -> tuple[OutputPlan, ...]:
        return self._outputs

    @property
    def references(self) -> tuple[SourceColumn, ...]:
        """Every source column the query reads, including those in conditions and joins."""
        return self._references

    @property
    def tables(self) -> tuple[tuple[str, str], ...]:
        """Reflected `(schema, table)` names the query reads."""
        return self._tables

    @property
    def max_rows(self) -> int:
        return self._max_rows

    @property
    def ast(self) -> exp.Select:
        return self._ast.copy()


def _check_row_limit(max_rows: int, runtime: RuntimeConfig) -> None:
    if max_rows < 1:
        raise DomainError(
            ErrorCode.INVALID_ARGUMENT,
            "max_rows must be at least 1.",
            f"Use a value between 1 and {runtime.hard_max_rows}.",
        )
    if max_rows > runtime.hard_max_rows:
        raise DomainError(
            ErrorCode.RESULT_LIMIT_EXCEEDED,
            f"max_rows exceeds the configured hard limit of {runtime.hard_max_rows}.",
            f"Use a value between 1 and {runtime.hard_max_rows}.",
        )


def _cap_rows(query: exp.Select, max_rows: int) -> None:
    fetch = max_rows + 1  # one extra row proves truncation without unbounded buffering
    limit = query.args.get("limit")
    requested = int(str(limit.expression.this)) if limit is not None else fetch
    query.set("limit", exp.Limit(expression=exp.Literal.number(min(requested, fetch))))


def _to_positional(
    query: exp.Select, parameters: dict[str, Any], dialect: SqlDialect
) -> tuple[str, tuple[Any, ...]]:
    """Render the dialect bind markers and order the values by their position in the generated text.

    Each placeholder is generated as a random one-time marker first, so user literals containing
    colons or marker-like text cannot be mistaken for binds.
    """
    nonce = secrets.token_hex(8)
    rendered = query.copy()
    markers: dict[str, str] = {}
    for placeholder in list(rendered.find_all(exp.Placeholder)):
        marker = f"__bind_{nonce}_{len(markers)}__"
        markers[marker] = str(placeholder.this)
        placeholder.replace(exp.Var(this=marker))
    sql = rendered.sql(dialect=dialect.name)
    if dialect.escape_percent:
        sql = sql.replace("%", "%%")
    found = re.findall(rf"__bind_{nonce}_\d+__", sql)
    if len(found) != len(markers) or set(found) != set(markers):
        raise reject(Reason.BIND_UNSAFE)
    for marker in found:
        sql = sql.replace(marker, dialect.bind_marker, 1)
    return sql, tuple(parameters[markers[marker]] for marker in found)


def issue_validated_query(
    analyzed: AnalyzedQuery,
    decision: PolicyDecision,
    *,
    alias: str,
    database: str,
    max_rows: int,
    runtime: RuntimeConfig,
    limits: ParserLimits,
    dialect: SqlDialect = SQLSERVER,
    tables: tuple[tuple[str, str], ...] = (),
) -> ValidatedQuery:
    """Rewrite tokens to binds, cap rows, re-validate, and generate SQL from the final AST.

    Consumes `analyzed.query`: token literals are replaced in place.
    """
    _check_row_limit(max_rows, runtime)
    query = analyzed.query
    parameters: dict[str, Any] = {}
    for site in decision.token_sites:
        name = f"pii_{len(parameters)}"
        parameters[name] = site.value
        site.literal.replace(exp.Placeholder(this=name))
    _cap_rows(query, max_rows)
    check_limits(query, limits)
    validate_allowlist(query, allow_placeholders=True)
    sql, ordered = _to_positional(query, parameters, dialect)
    if PREFIX in sql:
        raise reject(Reason.TOKEN_NOT_REPLACED)
    domains = decision.domains or (None,) * len(decision.protected)
    outputs = tuple(
        OutputPlan(output.label, output.kind, output.source, protected, domain)
        for output, protected, domain in zip(
            analyzed.outputs, decision.protected, domains, strict=True
        )
    )
    return ValidatedQuery(
        _SEAL,
        alias=alias,
        database=database,
        ast=query,
        sql=sql,
        parameters=ordered,
        outputs=outputs,
        references=tuple(ref.source for ref in analyzed.references),
        tables=tables,
        max_rows=max_rows,
    )
