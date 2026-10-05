from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, cast

from sqlglot import exp
from sqlglot.errors import OptimizeError, SqlglotError
from sqlglot.optimizer.qualify import qualify

from sql_safe_mcp.security.dialect import SqlDialect
from sql_safe_mcp.security.parser import (
    ParserLimits,
    check_limits,
    reject,
    validate_allowlist,
)
from sql_safe_mcp.security.reasons import Reason
from sql_safe_mcp.security.schema import TableSchema


@dataclass(frozen=True, slots=True)
class SourceColumn:
    schema: str
    table: str
    column: str


@dataclass(frozen=True, slots=True)
class OutputColumn:
    label: str
    kind: Literal["column", "count", "literal"]
    source: SourceColumn | None
    binding: str | None = None  # table alias/name the source column was read through


@dataclass(frozen=True, slots=True)
class ColumnRef:
    node: exp.Column
    source: SourceColumn


@dataclass(frozen=True, slots=True)
class AnalyzedQuery:
    query: exp.Select
    outputs: tuple[OutputColumn, ...]
    references: tuple[ColumnRef, ...]


@dataclass(frozen=True, slots=True)
class _Binding:
    name: str
    table: TableSchema


def _identifier(name: str) -> exp.Identifier:
    return exp.to_identifier(name, quoted=True)


def _collect(query: exp.Select, schemas: Sequence[TableSchema]) -> list[_Binding]:
    nodes: list[exp.Table] = []
    from_ = query.args.get("from_")
    if from_ is not None:
        nodes.append(from_.this)
    nodes += [join.this for join in query.args.get("joins") or []]
    if len(nodes) != len(schemas):
        raise reject(Reason.TABLE_RESOLUTION_MISMATCH)
    bindings: list[_Binding] = []
    seen: set[str] = set()
    for node, table in zip(nodes, schemas, strict=True):
        name = node.alias or table.name
        if name.casefold() in seen:
            raise reject(Reason.DUPLICATE_BINDING)
        seen.add(name.casefold())
        bindings.append(_Binding(name, table))
    return bindings


def _canonical_column(binding: _Binding, name: str) -> str | None:
    matches = [column for column in binding.table.columns if column.casefold() == name.casefold()]
    return matches[0] if len(matches) == 1 else None


def _resolve(column: exp.Column, bindings: Sequence[_Binding]) -> tuple[_Binding, str]:
    name = column.name
    qualifier = column.table
    if qualifier:
        matching = [b for b in bindings if b.name.casefold() == qualifier.casefold()]
        if len(matching) != 1:
            raise reject(Reason.QUALIFIER_UNKNOWN)
        canonical = _canonical_column(matching[0], name)
        if canonical is None:
            raise reject(Reason.COLUMN_NOT_FOUND)
        return matching[0], canonical
    candidates = [
        (binding, canonical)
        for binding in bindings
        if (canonical := _canonical_column(binding, name)) is not None
    ]
    if len(candidates) != 1:
        raise reject(Reason.COLUMN_AMBIGUOUS)
    return candidates[0]


def _rewrite(column: exp.Column, binding: _Binding, canonical: str) -> SourceColumn:
    column.set("this", _identifier(canonical))
    column.set("table", _identifier(binding.name))
    return SourceColumn(binding.table.schema, binding.table.name, canonical)


def _expand_stars(query: exp.Select, bindings: Sequence[_Binding]) -> None:
    expanded: list[exp.Expression] = []
    for projection in query.expressions:
        if isinstance(projection, exp.Star):
            chosen = list(bindings)
        elif isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star):
            chosen = [b for b in bindings if b.name.casefold() == projection.table.casefold()]
            if len(chosen) != 1:
                raise reject(Reason.QUALIFIER_UNKNOWN)
        else:
            expanded.append(projection)
            continue
        expanded.extend(
            exp.Column(this=_identifier(name), table=_identifier(binding.name))
            for binding in chosen
            for name in binding.table.columns
        )
    query.set("expressions", expanded)


def _analyze_projections(
    query: exp.Select, bindings: Sequence[_Binding], refs: list[ColumnRef]
) -> list[OutputColumn]:
    outputs: list[OutputColumn] = []
    for index, projection in enumerate(query.expressions, start=1):
        value = projection.this if isinstance(projection, exp.Alias) else projection
        alias = projection.alias if isinstance(projection, exp.Alias) else ""
        if isinstance(value, exp.Column):
            binding, canonical = _resolve(value, bindings)
            source = _rewrite(value, binding, canonical)
            refs.append(ColumnRef(value, source))
            outputs.append(OutputColumn(alias or canonical, "column", source, binding.name))
        elif isinstance(value, exp.Count):
            outputs.append(OutputColumn(alias or f"column_{index}", "count", None))
        elif isinstance(value, exp.Literal | exp.Null | exp.Neg):
            outputs.append(OutputColumn(alias or f"column_{index}", "literal", None))
        else:
            # Fail closed: a projection whose source cannot be traced is never a "literal".
            raise reject(Reason.PROJECTION_UNSUPPORTED)
    return outputs


def _resolve_order_column(
    column: exp.Column,
    bindings: Sequence[_Binding],
    outputs: Sequence[OutputColumn],
) -> SourceColumn:
    if not column.table:
        matches = [
            output for output in outputs if output.label.casefold() == column.name.casefold()
        ]
        if matches:
            # SQL Server resolves an unqualified ORDER BY name against output labels first.
            if len(matches) != 1 or matches[0].source is None:
                raise reject(Reason.ORDER_OUTPUT_AMBIGUOUS)
            source = matches[0].source
            binding = next(b for b in bindings if b.name == matches[0].binding)
            return _rewrite(column, binding, source.column)
    binding, canonical = _resolve(column, bindings)
    return _rewrite(column, binding, canonical)


def _cross_check(query: exp.Select, schemas: Sequence[TableSchema], dialect: SqlDialect) -> None:
    catalog: dict[str, dict] = {}
    for table in schemas:
        columns = dict.fromkeys(table.columns, "varchar")
        if dialect.has_schema:
            catalog.setdefault(table.schema, {})[table.name] = columns
        else:
            catalog[table.name] = columns
    try:
        qualify(
            query.copy(),
            schema=cast(dict[str, object], catalog),
            dialect=f"{dialect.name}, normalization_strategy = case_sensitive",
            validate_qualify_columns=True,
            expand_stars=False,
        )
    except (OptimizeError, SqlglotError) as exc:
        raise reject(Reason.QUALIFY_FAILED) from exc


def analyze_query(
    query: exp.Select,
    schemas: Sequence[TableSchema],
    limits: ParserLimits,
    dialect: SqlDialect,
) -> AnalyzedQuery:
    """Expand stars, resolve every column to a reflected source, and rebuild canonical names.

    The input query is not modified. Unknown or ambiguous lineage raises QUERY_REJECTED.
    """
    working = query.copy()
    bindings = _collect(working, schemas)
    _expand_stars(working, bindings)
    check_limits(working, limits)

    refs: list[ColumnRef] = []
    outputs = _analyze_projections(working, bindings, refs)

    for join in working.args.get("joins") or []:
        for column in join.args["on"].find_all(exp.Column):
            binding, canonical = _resolve(column, bindings)
            refs.append(ColumnRef(column, _rewrite(column, binding, canonical)))
    where = working.args.get("where")
    if where is not None:
        for column in where.find_all(exp.Column):
            binding, canonical = _resolve(column, bindings)
            refs.append(ColumnRef(column, _rewrite(column, binding, canonical)))
    order = working.args.get("order")
    if order is not None:
        for column in order.find_all(exp.Column):
            refs.append(ColumnRef(column, _resolve_order_column(column, bindings, outputs)))

    validate_allowlist(working)
    _cross_check(working, schemas, dialect)
    return AnalyzedQuery(working, tuple(outputs), tuple(refs))
