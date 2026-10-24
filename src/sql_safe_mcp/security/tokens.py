from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable, Mapping
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any, overload
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.errors import DomainError, ErrorCode

PREFIX = "pii:v1:"
MAX_TOKEN_CHARS = 4096
_NONCE_BYTES = 12
_KEY_BYTES = 32
_PAYLOAD_VERSION = 1
# Payload is padded to a multiple of _PAD_BLOCK bytes so token length reveals only the bucket;
# _PAD_FIELD_BYTES is the size of the empty `,"p":""` field added to the unpadded payload.
_PAD_BLOCK = 32
_PAD_FIELD_BYTES = len(b',"p":""')
_PADDED_KEYS = {"v", "t", "d", "p"}


def _invalid_token() -> DomainError:
    return DomainError(
        ErrorCode.INVALID_PII_TOKEN,
        "The PII token is invalid for this server.",
        "Use a token returned by execute_sql for the same server alias.",
    )


def _unsupported_value() -> DomainError:
    return DomainError(
        ErrorCode.QUERY_REJECTED,
        "Query rejected: a protected column contains a value that cannot be tokenized.",
        "Do not select this protected column.",
    )


def _dump(document: dict[str, Any]) -> bytes:
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )


def _reject_constant(_: str) -> Any:
    raise ValueError("non-finite JSON number")


def _encode_float(value: float) -> float:
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("non-finite float")
    return value


def _identity_check(_value: Any, _data: Any) -> bool:
    return True


def _bytes_check(value: bytes, data: str) -> bool:
    return base64.b64encode(value).decode("ascii") == data


def _finite_decimal(value: Decimal, data: str) -> bool:
    return value.is_finite() and str(value) == data


# tag -> (python type, to JSON data, from JSON data)
_CODECS: dict[type, tuple[str, Callable[[Any], Any]]] = {
    str: ("str", lambda v: v),
    bool: ("bool", lambda v: v),
    int: ("int", lambda v: v),
    float: ("float", _encode_float),
    Decimal: ("decimal", str),
    date: ("date", date.isoformat),
    datetime: ("datetime", datetime.isoformat),
    time: ("time", time.isoformat),
    UUID: ("uuid", str),
    bytes: ("bytes", lambda v: base64.b64encode(v).decode("ascii")),
}
# tag -> (JSON type of `d`, parser, canonical-form check); interpreted at decode time by
# _decode_value so every branch runs (and can be verified) per call.
_DECODERS: dict[str, tuple[type, Callable[[Any], Any], Callable[[Any, Any], bool]]] = {
    "str": (str, lambda d: d, _identity_check),
    "bool": (bool, lambda d: d, _identity_check),
    "int": (int, lambda d: d, _identity_check),
    "float": (float, lambda d: d, _identity_check),
    "decimal": (str, Decimal, _finite_decimal),
    "date": (str, date.fromisoformat, lambda v, d: v.isoformat() == d),
    "datetime": (str, datetime.fromisoformat, lambda v, d: v.isoformat() == d),
    "time": (str, time.fromisoformat, lambda v, d: v.isoformat() == d),
    "uuid": (str, UUID, lambda v, d: str(v) == d),
    "bytes": (str, lambda d: base64.b64decode(d, validate=True), _bytes_check),
}


def _decode_value(tag: str, data: Any) -> Any:
    kind, parse, check = _DECODERS[tag]
    if type(data) is not kind:
        raise ValueError("wrong payload type")
    value = parse(data)
    if not check(value, data):
        raise ValueError("non-canonical payload")
    return value


class TokenCodec:
    """AES-256-GCM tokens for one server alias; the alias is authenticated as AAD."""

    __slots__ = ("_aad", "_aead", "_alias")

    def __init__(self, alias: str, key: bytes) -> None:
        if len(key) != _KEY_BYTES:
            raise ValueError(f"PII key must be {_KEY_BYTES} bytes")
        self._alias = alias
        self._aead = AESGCM(key)
        self._aad = f"pii:v1\x00{alias}".encode()

    def __repr__(self) -> str:
        return f"TokenCodec(alias={self._alias!r})"

    @property
    def alias(self) -> str:
        return self._alias

    @overload
    def encrypt(self, value: None) -> None: ...

    @overload
    def encrypt(self, value: object) -> str: ...

    def encrypt(self, value: object) -> str | None:
        """Tokenize a scalar; NULL stays None. Unsupported values fail closed."""
        if value is None:
            return None
        entry = _CODECS.get(type(value))
        if entry is None:
            raise _unsupported_value()
        tag, to_data = entry
        try:
            document: dict[str, Any] = {"v": _PAYLOAD_VERSION, "t": tag, "d": to_data(value)}
            unpadded = _dump(document)
            document["p"] = "0" * (-(len(unpadded) + _PAD_FIELD_BYTES) % _PAD_BLOCK)
            payload = _dump(document)
        except (ValueError, OverflowError) as exc:
            raise _unsupported_value() from exc
        nonce = os.urandom(_NONCE_BYTES)
        sealed = nonce + self._aead.encrypt(nonce, payload, self._aad)
        token = PREFIX + base64.urlsafe_b64encode(sealed).decode("ascii").rstrip("=")
        if len(token) > MAX_TOKEN_CHARS:
            raise _unsupported_value()
        return token

    def decrypt(self, token: str) -> object:
        """Return the value; every failure raises the same INVALID_PII_TOKEN error."""
        try:
            return self._decrypt(token)
        except Exception:
            raise _invalid_token() from None

    def _decrypt(self, token: str) -> object:
        if len(token) > MAX_TOKEN_CHARS or not token.startswith(PREFIX):
            raise ValueError
        body = token[len(PREFIX) :]
        if not body.isascii():
            raise ValueError
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != body:
            raise ValueError
        if len(raw) < _NONCE_BYTES + 16:
            raise ValueError
        nonce, sealed = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        payload = self._aead.decrypt(nonce, sealed, self._aad)
        document = json.loads(payload.decode("utf-8"), parse_constant=_reject_constant)
        if not isinstance(document, dict) or set(document) not in ({"v", "t", "d"}, _PADDED_KEYS):
            raise ValueError
        padding = document.get("p", "")
        if type(padding) is not str or padding.strip("0"):
            raise ValueError
        version = document["v"]
        if type(version) is not int or version != _PAYLOAD_VERSION:
            raise ValueError
        return _decode_value(document["t"], document["d"])


class TokenKeyRegistry:
    """One codec per all_pii_safe alias; a codec never sees another alias's key."""

    __slots__ = ("_codecs",)

    def __init__(self, codecs: Mapping[str, TokenCodec]) -> None:
        self._codecs = dict(codecs)

    @classmethod
    def from_config(cls, config: AppConfig) -> TokenKeyRegistry:
        codecs: dict[str, TokenCodec] = {}
        for alias, server in config.servers.items():
            key = server.key_bytes()
            if key is not None:
                codecs[alias] = TokenCodec(alias, key)
        return cls(codecs)

    def __repr__(self) -> str:
        return f"TokenKeyRegistry(aliases={sorted(self._codecs)!r})"

    def codec_for(self, alias: str) -> TokenCodec:
        try:
            return self._codecs[alias]
        except KeyError:
            raise DomainError(
                ErrorCode.ACCESS_LEVEL_DENIED,
                "PII tokens are not available for this server.",
                "Use a server configured with access_level all_pii_safe.",
            ) from None
