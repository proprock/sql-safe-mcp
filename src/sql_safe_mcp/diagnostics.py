from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from urllib.parse import quote

from sqlalchemy.engine import make_url

_MAX_MESSAGE_CHARS = 500
# C0 and C1 controls (NEL is \x85) plus the Unicode line and paragraph separators.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")
_WORD = re.compile(r"\w")
_LONG_DIGITS = re.compile(r"\d{6,}")
_LOG_FIELD_UNSAFE = re.compile(r"[^\w.$#@-]")


def log_field(value: str | None) -> str:
    """Keep a caller- or metadata-supplied name on one field of a log line.

    ``None`` and the empty string are ``-``, so the field is never empty."""
    return _LOG_FIELD_UNSAFE.sub("?", value) if value else "-"


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


def _is_quote(message: str, index: int) -> bool:
    """Whether the ``'`` or ``"`` at ``index`` can open or close a quoted value.

    An apostrophe between two word characters (Can't, d'ouvrir, dell'utente, O'Brien) is part of a
    word, in any language. The one exception is a capital N standing alone, the T-SQL prefix of
    N'...'; a lowercase n' is French elision.
    """
    if message[index] == '"':
        return True
    before = message[index - 1] if index else ""
    after = message[index + 1] if index + 1 < len(message) else ""
    if not (_WORD.match(before) and _WORD.match(after)):
        return True
    return before == "N" and (index == 1 or not _WORD.match(message[index - 2]))


def _first_span(text: str) -> tuple[int, int | None] | None:
    """Bounds of the first quoted span: an opening quote to the last matching quote after it.

    The end is ``None`` when the opening quote has no match: the span runs to the end of the text.
    """
    for start, char in enumerate(text):
        if char in ("'", '"') and _is_quote(text, start):
            for end in range(len(text) - 1, start, -1):
                if text[end] == char and _is_quote(text, end):
                    return start, end
            return start, None
    return None


def _mask_quoted(message: str) -> str:
    """Replace each quoted span with ``'***'``, from an opening quote to the LAST matching quote.

    Greedy on purpose: when a stray apostrophe is misread as a quote, the text between values is
    masked as well, but a value is never left in clear. Pairing each quote with the nearest one
    would shift every later pair and expose the values. A quote with no match is a value cut off
    by the driver or a false opener: the rest of the message is masked (over-masking by design).
    """
    masked: list[str] = []
    rest = message
    while (span := _first_span(rest)) is not None:
        start, end = span
        if end is None:
            return "".join(masked) + f"{rest[:start]}{rest[start]}***"
        masked += [rest[:start], f"{rest[start]}***{rest[start]}"]
        rest = rest[end + 1 :]
    return "".join(masked) + rest


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
    message = _mask_quoted(message)
    message = _LONG_DIGITS.sub("***", message)
    message = _CONTROL_CHARACTERS.sub(" ", message).strip()
    if len(message) > _MAX_MESSAGE_CHARS:
        message = message[:_MAX_MESSAGE_CHARS] + "..."
    return f"{name}{code} message={message}"
