from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time
from decimal import Decimal
from fnmatch import fnmatchcase
from uuid import UUID

from sqlglot import exp

from sql_safe_mcp.config import PiiConfig, PiiRule
from sql_safe_mcp.security.lineage import AnalyzedQuery, ColumnRef, SourceColumn
from sql_safe_mcp.security.parser import reject
from sql_safe_mcp.security.reasons import Reason
from sql_safe_mcp.security.schema import TypeClass
from sql_safe_mcp.security.tokens import PREFIX, TokenCodec

# Exact driver value type of a decrypted token -> the column class it may be compared with.
# bool is an int subclass and datetime a date subclass, so lookups use type(), never isinstance().
_VALUE_CLASSES: dict[type, TypeClass] = {
    str: "string",
    bool: "bool",
    int: "integer",
    float: "float",
    Decimal: "decimal",
    date: "date",
    datetime: "datetime",
    time: "time",
    UUID: "uuid",
    bytes: "binary",
}


@dataclass(frozen=True, slots=True)
class TokenSite:
    """A token literal in an allowed predicate position and its decrypted bind value."""

    literal: exp.Literal
    value: object = field(repr=False)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    protected: tuple[bool, ...]
    token_sites: tuple[TokenSite, ...]
    # Token domain per output; None for an unprotected output.
    domains: tuple[str | None, ...] = ()


class PiiPolicy:
    """Decides protected-column usage from source lineage and configured rules only."""

    def __init__(self, database: str, config: PiiConfig, codec: TokenCodec) -> None:
        self._database = database.casefold()
        self._config = config
        self._codec = codec

    def _matching(self, rules: Sequence[PiiRule], source: SourceColumn) -> list[PiiRule]:
        schema = source.schema.casefold()
        table = source.table.casefold()
        column = source.column.casefold()
        matched: list[PiiRule] = []
        for rule in rules:
            if rule.database != "*" and rule.database.casefold() != self._database:
                continue
            if rule.schema_ is not None and rule.schema_.casefold() != schema:
                continue
            if fnmatchcase(table, rule.table.casefold()) and (
                rule.columns == ["*"] or column in {item.casefold() for item in rule.columns}
            ):
                matched.append(rule)
        return matched

    def _matches(self, rules: Sequence[PiiRule], source: SourceColumn) -> bool:
        return bool(self._matching(rules, source))

    def is_denied(self, source: SourceColumn) -> bool:
        return self._matches(self._config.deny, source)

    def protected_domain(self, source: SourceColumn) -> str | None:
        """The token domain of a protected column, or None; the default domain is the alias."""
        matched = self._matching(self._config.rules, source)
        if matched:
            domains = {rule.domain or self._codec.alias for rule in matched}
            if len(domains) > 1:
                raise reject(Reason.DOMAIN_CONFLICT)
            return domains.pop()
        if self._config.mode == "deny-by-default" and not self._matches(
            self._config.exposed_columns, source
        ):
            return self._codec.alias
        return None

    def evaluate(self, analyzed: AnalyzedQuery) -> PolicyDecision:
        for ref in analyzed.references:
            if self.is_denied(ref.source):
                raise reject(Reason.COLUMN_DENIED)
        sites: list[TokenSite] = []
        for ref in analyzed.references:
            domain = self.protected_domain(ref.source)
            if domain is not None:
                sites.extend(self._check_protected(ref, domain))
        consumed = {id(site.literal) for site in sites}
        for literal in analyzed.query.find_all(exp.Literal):
            if (
                literal.is_string
                and str(literal.this).startswith(PREFIX)
                and id(literal) not in consumed
            ):
                raise reject(Reason.TOKEN_OUTSIDE_PROTECTED)
        domains = tuple(
            None if output.source is None else self.protected_domain(output.source)
            for output in analyzed.outputs
        )
        protected = tuple(domain is not None for domain in domains)
        return PolicyDecision(protected, tuple(sites), domains)

    def _check_protected(self, ref: ColumnRef, domain: str) -> list[TokenSite]:
        column = ref.node
        parent = column.parent
        if isinstance(parent, exp.Select):
            return []
        if isinstance(parent, exp.Alias) and isinstance(parent.parent, exp.Select):
            return []
        if not _in_where(column):
            raise reject(Reason.PROTECTED_POSITION)
        if isinstance(parent, exp.EQ) and parent.this is column:
            return [self._token_site(parent.expression, ref.source, domain)]
        if isinstance(parent, exp.In) and parent.this is column and parent.expressions:
            return [self._token_site(item, ref.source, domain) for item in parent.expressions]
        raise reject(Reason.PROTECTED_POSITION)

    def _token_site(self, node: exp.Expression, source: SourceColumn, domain: str) -> TokenSite:
        if (
            not isinstance(node, exp.Literal)
            or not node.is_string
            or not str(node.this).startswith(PREFIX)
        ):
            raise reject(Reason.PROTECTED_NEEDS_TOKEN)
        # Decrypt first: a forged token keeps its INVALID_PII_TOKEN error and priority.
        value = self._codec.decrypt(str(node.this), domain)
        if _VALUE_CLASSES.get(type(value)) != source.type_class:
            raise reject(Reason.TOKEN_TYPE_MISMATCH)
        return TokenSite(node, value)


def _in_where(node: exp.Expression) -> bool:
    current = node.parent
    while current is not None:
        if isinstance(current, exp.Where):
            return True
        if isinstance(current, exp.Join | exp.Order | exp.Select):
            return False
        current = current.parent
    return False
