from __future__ import annotations

import base64
import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any, Protocol
from uuid import UUID

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.models import ResultEncoding
from sql_safe_mcp.security.lineage import SourceColumn
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.security.validated_query import ValidatedQuery


class _Result(Protocol):
    def keys(self) -> Any: ...

    def fetchmany(self, size: int) -> Sequence[Any]: ...

    def close(self) -> None: ...


class SqlConnection(Protocol):
    """The part of a SQLAlchemy Core connection the executor uses."""

    def exec_driver_sql(self, statement: str, parameters: tuple[Any, ...]) -> _Result: ...


@dataclass(frozen=True, slots=True)
class ResultColumn:
    name: str
    source: SourceColumn | None
    protected: bool
    encoding: ResultEncoding


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    columns: tuple[ResultColumn, ...]
    rows: tuple[tuple[Any, ...], ...]
    truncated: bool


def _unsupported_result() -> DomainError:
    return DomainError(
        ErrorCode.DATABASE_ERROR,
        "The result contains a value type that is not supported.",
        "Select different columns.",
    )


def _encode(value: Any) -> tuple[Any, ResultEncoding]:
    """Return the JSON-safe form and encoding name of one non-null, unprotected value."""
    kind = type(value)
    if kind in (str, bool, int):
        return value, "json"
    if kind is float:
        if not math.isfinite(value):
            raise _unsupported_result()
        return value, "json"
    if kind is Decimal:
        if not value.is_finite():
            raise _unsupported_result()
        return str(value), "decimal"
    if kind is datetime:
        return value.isoformat(), "datetime"
    if kind is date:
        return value.isoformat(), "date"
    if kind is time:
        return value.isoformat(), "time"
    if kind is timedelta:  # MySQL TIME; only a time of day fits the `time` encoding
        if not timedelta(0) <= value < timedelta(days=1):
            raise _unsupported_result()
        return (datetime.min + value).time().isoformat(), "time"
    if kind is UUID:
        return str(value), "uuid"
    if kind in (bytes, bytearray, memoryview):
        return base64.b64encode(bytes(value)).decode("ascii"), "base64"
    raise _unsupported_result()


def execute_validated(
    connection: SqlConnection, query: ValidatedQuery, codec: TokenCodec
) -> ExecutionResult:
    """Run a ValidatedQuery: generated SQL and binds only, at most max_rows + 1 rows buffered."""
    if not isinstance(query, ValidatedQuery):
        raise TypeError("the executor accepts only ValidatedQuery")
    if codec.alias != query.alias:
        raise TypeError("the token codec belongs to a different server alias")

    result = connection.exec_driver_sql(query.sql, query.parameters)
    try:
        if len(result.keys()) != len(query.outputs):
            raise _unsupported_result()
        fetched = result.fetchmany(query.max_rows + 1)
        truncated = len(fetched) > query.max_rows
        encodings: list[ResultEncoding | None] = [None] * len(query.outputs)
        suppressed = [False] * len(query.outputs)
        threshold = query.min_count_cell
        rows: list[tuple[Any, ...]] = []
        for raw in fetched[: query.max_rows]:
            cells: list[Any] = []
            for index, (plan, value) in enumerate(zip(query.outputs, tuple(raw), strict=True)):
                if value is None:
                    cells.append(None)
                elif threshold and plan.kind == "count":
                    if type(value) is not int:
                        raise _unsupported_result()
                    if 0 < value < threshold:
                        suppressed[index] = True
                        cells.append(None)
                    else:
                        encodings[index] = "json"
                        cells.append(value)
                elif plan.protected:
                    cells.append(codec.encrypt(value, plan.domain))
                else:
                    encoded, encoding = _encode(value)
                    if encodings[index] not in (None, encoding):
                        raise _unsupported_result()
                    encodings[index] = encoding
                    cells.append(encoded)
            rows.append(tuple(cells))
    finally:
        result.close()

    columns = tuple(
        ResultColumn(
            plan.label,
            plan.source,
            plan.protected,
            "token"
            if plan.protected
            else "suppressed"
            if suppressed[index]
            else (encodings[index] or "json"),
        )
        for index, plan in enumerate(query.outputs)
    )
    return ExecutionResult(columns, tuple(rows), truncated)
