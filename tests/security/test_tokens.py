import base64
import json
from datetime import UTC, date, datetime, time
from decimal import Decimal
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given
from hypothesis import strategies as st

from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.tokens import MAX_TOKEN_CHARS, TokenCodec, TokenKeyRegistry

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))

VALUES = [
    "plain",
    "",
    "x'; DROP TABLE Canary;--",
    "üñí \U0001f600 ‮",
    0,
    -7,
    2**70,
    True,
    False,
    1.5,
    Decimal("12345.67890"),
    date(2024, 2, 29),
    datetime(2024, 2, 29, 13, 14, 15, 123456),
    datetime(2024, 2, 29, 13, 14, 15, tzinfo=UTC),
    time(1, 2, 3, 4),
    UUID("12345678-1234-5678-1234-567812345678"),
    b"\x00\xff\x10",
]


def invalid(token: str, codec: TokenCodec) -> DomainError:
    with pytest.raises(DomainError) as info:
        codec.decrypt(token)
    assert info.value.code is ErrorCode.INVALID_PII_TOKEN
    return info.value


@pytest.mark.parametrize("value", VALUES, ids=[repr(v)[:30] for v in VALUES])
def test_round_trip_preserves_type_and_value(value: object) -> None:
    codec = TokenCodec("srv", KEY)
    token = codec.encrypt(value)
    assert token.startswith("pii:v1:")
    decoded = codec.decrypt(token)
    assert decoded == value
    assert type(decoded) is type(value)


def test_null_is_not_tokenized() -> None:
    assert TokenCodec("srv", KEY).encrypt(None) is None


def test_nonce_is_random() -> None:
    codec = TokenCodec("srv", KEY)
    assert codec.encrypt("same") != codec.encrypt("same")


def _raw_len(token: str) -> int:
    body = token.removeprefix("pii:v1:")
    return len(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def test_token_layout_is_nonce_padded_ciphertext_tag() -> None:
    token = TokenCodec("srv", KEY).encrypt("a")
    assert _raw_len(token) == 12 + 32 + 16


def test_token_length_reveals_only_the_32_byte_bucket() -> None:
    codec = TokenCodec("srv", KEY)
    # Payload is 31 + len(s) bytes: {"v":1,"t":"str","d":""} (24) + ,"p":"" (7) + s.
    lengths = {n: _raw_len(codec.encrypt("a" * n)) for n in range(0, 100)}
    assert {lengths[n] for n in range(0, 2)} == {12 + 32 + 16}
    assert {lengths[n] for n in range(2, 34)} == {12 + 64 + 16}
    assert {lengths[n] for n in range(34, 66)} == {12 + 96 + 16}
    assert lengths[66] == 12 + 128 + 16
    assert all((lengths[n] - 12 - 16) % 32 == 0 for n in lengths)


def test_all_value_types_are_padded_to_the_block() -> None:
    codec = TokenCodec("srv", KEY)
    for value in VALUES:
        assert (_raw_len(codec.encrypt(value)) - 28) % 32 == 0


@given(st.text(max_size=300))
def test_token_length_depends_only_on_payload_bucket(text: str) -> None:
    codec = TokenCodec("srv", KEY)
    unpadded = len(
        json.dumps(
            {"v": 1, "t": "str", "d": text}, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )
    blocks = -(-(unpadded + len(b',"p":""')) // 32)
    assert _raw_len(codec.encrypt(text)) == 12 + blocks * 32 + 16


def test_legacy_token_without_padding_field_is_accepted() -> None:
    payload = json.dumps({"v": 1, "t": "str", "d": "old"}, separators=(",", ":")).encode()
    assert TokenCodec("srv", KEY).decrypt(_forge("srv", payload)) == "old"


def test_padding_field_with_zeros_is_accepted_including_empty() -> None:
    for pad in ("", "0", "0" * 40):
        payload = json.dumps({"v": 1, "t": "str", "d": "x", "p": pad}, separators=(",", ":"))
        assert TokenCodec("srv", KEY).decrypt(_forge("srv", payload.encode())) == "x"


@pytest.mark.parametrize("pad", ["1", "00a", " ", "0 ", 0, None, ["0"]])
def test_non_canonical_padding_is_rejected(pad: object) -> None:
    payload = json.dumps({"v": 1, "t": "str", "d": "x", "p": pad}, separators=(",", ":"))
    invalid(_forge("srv", payload.encode()), TokenCodec("srv", KEY))


def test_token_is_bound_to_its_alias_even_with_the_same_key() -> None:
    token = TokenCodec("alpha", KEY).encrypt("secret")
    invalid(token, TokenCodec("beta", KEY))
    assert TokenCodec("alpha", KEY).decrypt(token) == "secret"


def test_wrong_key_is_rejected_and_rotation_invalidates_tokens() -> None:
    token = TokenCodec("srv", KEY).encrypt("secret")
    invalid(token, TokenCodec("srv", OTHER_KEY))


def _corruptions(token: str) -> list[str]:
    body = token.removeprefix("pii:v1:")
    flipped = [
        "pii:v1:" + body[:i] + ("A" if body[i] != "A" else "B") + body[i + 1 :]
        for i in range(0, len(body), 3)
    ]
    return [
        *flipped,
        "",
        "pii:v1:",
        "pii:v2:" + body,
        "PII:v1:" + body,
        "pii:v1:" + body[:-4],
        "pii:v1:" + body + "AAAA",
        "pii:v1:" + body + "=",
        "pii:v1:" + body.replace("-", "+").replace("_", "/") + "\n",
        "pii:v1: " + body,
        "pii:v1:" + body + "é",
        "pii:v1:" + "!" * len(body),
        body,
        "pii:v1:" + "A" * (MAX_TOKEN_CHARS + 1),
        "\x00",
        "\ud800",
    ]


def test_every_malformed_or_tampered_token_gives_the_same_error() -> None:
    codec = TokenCodec("srv", KEY)
    errors = {repr(invalid(item, codec)) for item in _corruptions(codec.encrypt("secret" * 4))}
    assert len(errors) == 1
    assert "secret" not in next(iter(errors))


def test_wrong_key_wrong_alias_and_malformed_are_indistinguishable() -> None:
    token = TokenCodec("srv", KEY).encrypt("v")
    results = {
        repr(invalid(token, TokenCodec("srv", OTHER_KEY))),
        repr(invalid(token, TokenCodec("other", KEY))),
        repr(invalid("pii:v1:AAAA", TokenCodec("srv", KEY))),
    }
    assert len(results) == 1


def _forge(codec_alias: str, payload: bytes) -> str:
    nonce = bytes(12)
    aad = f"pii:v1\x00{codec_alias}".encode()
    sealed = AESGCM(KEY).encrypt(nonce, payload, aad)
    return "pii:v1:" + base64.urlsafe_b64encode(nonce + sealed).decode().rstrip("=")


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"[]",
        b'{"v":1,"t":"str"}',
        b'{"v":1,"t":"str","d":1}',
        b'{"v":2,"t":"str","d":"x"}',
        b'{"v":1,"t":"unknown","d":"x"}',
        b'{"v":1,"t":"str","d":"x","extra":1}',
        b'{"v":1,"t":"int","d":"1"}',
        b'{"v":1,"t":"int","d":true}',
        b'{"v":1,"t":"bool","d":1}',
        b'{"v":1,"t":"date","d":"nope"}',
        b'{"v":1,"t":"bytes","d":"!!"}',
        b'{"v":1,"t":"float","d":NaN}',
        b"\xff\xfe",
    ],
)
def test_authentic_but_invalid_payload_is_rejected(payload: bytes) -> None:
    invalid(_forge("srv", payload), TokenCodec("srv", KEY))


def test_forged_well_formed_payload_is_accepted_only_with_the_key() -> None:
    payload = json.dumps({"v": 1, "t": "str", "d": "ok"}, separators=(",", ":")).encode()
    assert TokenCodec("srv", KEY).decrypt(_forge("srv", payload)) == "ok"


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object(), [1], {"a": 1}, 1j])
def test_unsupported_values_fail_closed_without_leaking(value: object) -> None:
    with pytest.raises(DomainError) as info:
        TokenCodec("srv", KEY).encrypt(value)
    assert info.value.code is ErrorCode.QUERY_REJECTED


def test_oversized_plaintext_is_rejected() -> None:
    with pytest.raises(DomainError) as info:
        TokenCodec("srv", KEY).encrypt("x" * MAX_TOKEN_CHARS)
    assert info.value.code is ErrorCode.QUERY_REJECTED


def test_codec_rejects_bad_key_length_and_hides_key_in_repr() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        TokenCodec("srv", b"short")
    codec = TokenCodec("srv", KEY)
    assert KEY.hex() not in repr(codec) + str(codec)
    assert repr(KEY) not in repr(codec)


def _config(keys: dict[str, bytes | None]) -> AppConfig:
    servers = {}
    for alias, key in keys.items():
        server: dict[str, object] = {
            "engine": "sqlserver",
            "connection_url": "mssql+pyodbc://u:p@h/d?driver=x",
        }
        if key is not None:
            server.update(
                access_level="all_pii_safe",
                pii_key_env="K",
                pii={"rules": [{"database": "*", "table": "T", "columns": ["c"]}]},
                pii_key=base64.b64encode(key).decode(),
            )
        servers[alias] = server
    return AppConfig.model_validate({"version": 1, "servers": servers})


def test_registry_builds_codecs_only_for_all_pii_safe_aliases() -> None:
    registry = TokenKeyRegistry.from_config(_config({"a": KEY, "b": OTHER_KEY, "m": None}))
    token = registry.codec_for("a").encrypt("x")
    invalid(token, registry.codec_for("b"))
    for alias in ("m", "missing"):
        with pytest.raises(DomainError) as info:
            registry.codec_for(alias)
        assert info.value.code is ErrorCode.ACCESS_LEVEL_DENIED


def test_registry_repr_hides_keys() -> None:
    registry = TokenKeyRegistry.from_config(_config({"a": KEY}))
    assert KEY.hex() not in repr(registry)
    assert base64.b64encode(KEY).decode() not in repr(registry)
