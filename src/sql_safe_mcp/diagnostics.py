from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from urllib.parse import quote

from sqlalchemy.engine import make_url

_MAX_MESSAGE_CHARS = 500
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")
_QUOTED_LITERAL = re.compile(r"""(['"])(?:(?!\1).)*\1""", re.DOTALL)
_LONG_DIGITS = re.compile(r"\d{6,}")


def configure_logging(level: str, audit: bool = False) -> None:
    logging.getLogger("sql_safe_mcp").setLevel(level)
    # The audit trail is INFO, so it must survive a WARNING or ERROR package level.
    logging.getLogger("sql_safe_mcp.audit").setLevel(logging.INFO if audit else logging.NOTSET)
    # SQLAlchemy inherits the root level and would echo statements with bind values at DEBUG.
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    # At DEBUG the MCP SDK logs a malformed JSON-RPC frame whole, with any SQL, tokens or rows.
    sdk = logging.getLogger("mcp")
    sdk.setLevel(level)
    sdk.setLevel(max(logging.INFO, sdk.level))


def secrets_for(url: str, alias: str) -> tuple[tuple[str, str], ...]:
    """Redactions for a connection URL: credentials become ``***``, the host the server alias."""
    try:
        parsed = make_url(url)
    except Exception:
        return ()
    found: dict[str, str] = {}
    for value, replacement in (
        (parsed.password, "***"),
        (parsed.username, "***"),
        (parsed.host, alias),
    ):
        if value:
            found[value] = replacement
            found[quote(value, safe="")] = replacement
    return tuple(found.items())


def _driver_parts(exc: BaseException) -> tuple[str, str, str]:
    orig = getattr(exc, "orig", None) or exc
    args = orig.args
    if len(args) >= 2 and isinstance(args[0], int):
        return type(orig).__name__, f" code={args[0]}", str(args[1])
    if len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], str):
        return type(orig).__name__, f" sqlstate={args[0]}", args[1]
    return type(orig).__name__, "", str(orig)


def _secret_pattern(secret: str) -> str:
    # Whole-word only where the edge is a word character, so "sa" spares "usage" but a
    # password ending in punctuation is still removed.
    start = r"(?<!\w)" if re.match(r"\w", secret[0]) else ""
    end = r"(?!\w)" if re.match(r"\w", secret[-1]) else ""
    return f"{start}{re.escape(secret)}{end}"


def describe_error(
    exc: BaseException, redactions: Iterable[tuple[str, str]], *, include_message: bool = True
) -> str:
    """One log-safe line for a driver error: class, SQLSTATE or code, redacted message."""
    name, code, message = _driver_parts(exc)
    if not include_message:
        return f"{name}{code}"
    for secret, replacement in sorted(set(redactions), key=lambda pair: len(pair[0]), reverse=True):
        if secret:
            message = re.sub(
                _secret_pattern(secret),
                lambda _, text=replacement: text,
                message,
                flags=re.IGNORECASE,
            )
    # Drivers echo offending values in quotes or as long digit runs (SQL Server error 245 and
    # MySQL 1062/1292 do), so those are never logged.
    message = _QUOTED_LITERAL.sub(lambda match: f"{match[1]}***{match[1]}", message)
    message = _LONG_DIGITS.sub("***", message)
    message = _CONTROL_CHARACTERS.sub(" ", message).strip()
    if len(message) > _MAX_MESSAGE_CHARS:
        message = message[:_MAX_MESSAGE_CHARS] + "..."
    return f"{name}{code} message={message}"
