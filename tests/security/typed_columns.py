"""Typed column fixtures shared by the fake catalogs of the test suites."""

from __future__ import annotations

from collections.abc import Iterable

from sql_safe_mcp.security.schema import ColumnSchema, TypeClass

_KNOWN: dict[str, TypeClass] = {"id": "integer", "userid": "integer", "total": "decimal"}


def typed(names: Iterable[str], **overrides: TypeClass) -> list[ColumnSchema]:
    """`id`/`userid` are integers, `total` is a decimal, everything else is a string."""
    return [
        ColumnSchema(name, overrides.get(name, _KNOWN.get(name.casefold(), "string")))
        for name in names
    ]
