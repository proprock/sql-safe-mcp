"""Exact error behavior of configuration loading and PII key handling."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from sql_safe_mcp.config import AppConfig, load_config
from sql_safe_mcp.errors import DomainError, ErrorCode

URL = "mssql+pyodbc://u:p@sql/master?driver=x"


def _yaml(url: str = URL, extra: str = "", version: int = 1) -> str:
    return (
        f"version: {version}\n"
        "servers:\n"
        "  s:\n"
        "    engine: sqlserver\n"
        f"    connection_url: {url}\n"
        f"{extra}"
    )


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _error(path: Path, env: dict[str, str] | None = None) -> DomainError:
    with pytest.raises(DomainError) as info:
        load_config(path, {} if env is None else env)
    assert info.value.code is ErrorCode.CONFIG_ERROR
    return info.value


def test_missing_file_is_a_generic_config_error(tmp_path: Path) -> None:
    error = _error(tmp_path / "absent.yaml")
    assert error.public_message == "Invalid configuration file."
    assert error.hint is None


def test_malformed_yaml_is_a_generic_config_error(tmp_path: Path) -> None:
    assert _error(_write(tmp_path, "a: [unclosed")).public_message == "Invalid configuration file."


def test_embedded_missing_environment_variable_is_named(tmp_path: Path) -> None:
    error = _error(_write(tmp_path, _yaml(URL + "${SECRET}")))
    assert error.public_message == "Invalid configuration: missing environment variable SECRET"


def test_whole_value_missing_environment_variable_is_named(tmp_path: Path) -> None:
    error = _error(_write(tmp_path, _yaml("${SECRET_URL}")))
    assert error.public_message == "Invalid configuration: missing environment variable SECRET_URL"


def test_unresolvable_placeholder_is_rejected(tmp_path: Path) -> None:
    error = _error(_write(tmp_path, _yaml(URL + "${lower}")))
    assert error.public_message == (
        "Invalid configuration: invalid environment placeholder in connection_url"
    )


def test_malformed_connection_url_is_a_sanitized_config_error(tmp_path: Path) -> None:
    secret = "url-secret-marker"

    error = _error(_write(tmp_path, _yaml(f"'not a URL {secret}'")))

    assert error.public_message == (
        "Invalid configuration: servers.s: Value error, "
        "connection_url must be a valid SQLAlchemy URL"
    )
    assert secret not in str(error)


def test_special_characters_in_embedded_values_are_encoded(tmp_path: Path) -> None:
    path = _write(tmp_path, _yaml("mssql+pyodbc://u:${P}@h/d?driver=x"))
    config = load_config(path, {"P": "Xa/b c@d?e#f%g&h=i+j"})
    url = config.servers["s"].connection_url.get_secret_value()
    assert ":Xa%2Fb%20c%40d%3Fe%23f%25g%26h%3Di%2Bj@h" in url


def test_process_environment_is_used_when_none_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SMM_TEST_HOST", "envhost")
    path = _write(tmp_path, _yaml("mssql+pyodbc://u:p@${SMM_TEST_HOST}/d?driver=x"))
    config = load_config(path)
    assert "envhost" in config.servers["s"].connection_url.get_secret_value()


def test_non_ascii_configuration_is_read_as_utf8(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_bytes(("# caf\u00e9 \u4e2d\u6587\n" + _yaml()).encode("utf-8"))
    assert "s" in load_config(path, {}).servers


def test_validation_errors_list_each_location_and_message(tmp_path: Path) -> None:
    error = _error(_write(tmp_path, _yaml(extra="    bogus: 1\n", version=2)))
    assert error.public_message == (
        "Invalid configuration: version: Input should be 1; "
        "servers.s.bogus: Extra inputs are not permitted"
    )


def test_non_string_pii_key_env_is_a_config_error_not_a_crash(tmp_path: Path) -> None:
    error = _error(_write(tmp_path, _yaml(extra="    pii_key_env: 5\n")), {"5": "x"})
    assert error.public_message.startswith("Invalid configuration: missing PII key environment")


def test_a_missing_pii_key_variable_is_named_without_its_value(tmp_path: Path) -> None:
    error = _error(_write(tmp_path, _yaml(extra="    pii_key_env: NOPE\n")))
    assert error.public_message == (
        "Invalid configuration: missing PII key environment variable 'NOPE'"
    )


def _model(key: str) -> dict[str, object]:
    return {
        "version": 1,
        "servers": {
            "s": {
                "engine": "sqlserver",
                "access_level": "all_pii_safe",
                "connection_url": URL,
                "pii_key_env": "K",
                "pii": {"rules": [{"database": "*", "table": "T", "columns": ["c"]}]},
                "pii_key": key,
            }
        },
    }


def test_pii_key_must_be_strict_base64() -> None:
    good = base64.b64encode(bytes(range(32))).decode()
    AppConfig.model_validate(_model(good))
    noisy = good[:10] + "!" + good[10:]
    with pytest.raises(ValidationError):
        AppConfig.model_validate(_model(noisy))


def test_pii_key_must_decode_to_exactly_32_bytes() -> None:
    for size in (31, 33, 16, 64):
        key = base64.b64encode(bytes(size)).decode()
        with pytest.raises(ValidationError):
            AppConfig.model_validate(_model(key))


def test_duplicate_keys_across_aliases_are_rejected() -> None:
    key = base64.b64encode(bytes(range(32))).decode()
    model = _model(key)
    servers = model["servers"]
    assert isinstance(servers, dict)
    servers["t"] = dict(servers["s"])
    with pytest.raises(ValidationError, match="must be unique per server alias"):
        AppConfig.model_validate(model)


def _message(text: str, env: dict[str, str] | None = None) -> str:
    path = Path(__import__("tempfile").mkdtemp()) / "c.yaml"
    path.write_text(text, encoding="utf-8")
    return _error(path, env).public_message


def test_structure_errors_have_exact_messages() -> None:
    assert _message("- a\n- b\n") == "Invalid configuration: configuration root must be a mapping"
    assert (
        _message("version: 1\nservers: []\n") == "Invalid configuration: servers must be a mapping"
    )
    assert _message("version: 1\nservers:\n  s: x\n") == (
        "Invalid configuration: server 's' must be a mapping"
    )
    assert _message("version: 1\nservers:\n  s:\n    engine: sqlserver\n") == (
        "Invalid configuration: server 's' requires connection_url"
    )
    assert _message(_yaml(url="5")).startswith("Invalid configuration:")


def test_invalid_pii_key_values_have_exact_messages() -> None:
    extra = "    access_level: all_pii_safe\n    pii_key_env: K\n"
    assert _message(_yaml(extra=extra), {"K": "!!!not base64"}) == (
        "Invalid configuration: PII key for server 's' is not valid base64"
    )
    short = base64.b64encode(bytes(8)).decode()
    assert _message(_yaml(extra=extra), {"K": short}) == (
        "Invalid configuration: PII key for server 's' must decode to 32 bytes"
    )


def test_model_level_validation_errors_are_reported() -> None:
    def summary(model: dict[str, object]) -> str:
        with pytest.raises(ValidationError) as info:
            AppConfig.model_validate(model)
        return str(info.value)

    server = {"engine": "sqlserver", "connection_url": URL}
    assert "invalid server alias '_bad'" in summary({"version": 1, "servers": {"_bad": server}})
    assert "default_max_rows cannot exceed hard_max_rows" in summary(
        {
            "version": 1,
            "runtime": {"default_max_rows": 10, "hard_max_rows": 5},
            "servers": {"s": server},
        }
    )
    other = dict(server, connection_url="mysql+pymysql://u:p@h/d")
    assert "requires SQLAlchemy dialect 'mssql+pyodbc'" in summary(
        {"version": 1, "servers": {"s": other}}
    )
    metadata_with_pii = dict(server, pii_key_env="K")
    assert "metadata servers cannot configure" in summary(
        {"version": 1, "servers": {"s": metadata_with_pii}}
    )
    all_pii_safe_without_keys = dict(server, access_level="all_pii_safe")
    assert "all_pii_safe servers require pii_key_env and pii rules" in summary(
        {"version": 1, "servers": {"s": all_pii_safe_without_keys}}
    )


def _pii_summary(pii: dict[str, object]) -> str:
    server = dict(cast(dict[str, dict[str, object]], _model("x")["servers"])["s"])
    server["pii"] = pii
    server["pii_key"] = base64.b64encode(bytes(32)).decode()
    with pytest.raises(ValidationError) as info:
        AppConfig.model_validate({"version": 1, "servers": {"s": server}})
    return str(info.value)


def test_pii_rule_validation_errors_are_reported() -> None:
    def summary(rule: dict[str, object]) -> str:
        return _pii_summary({"rules": [rule]})

    base: dict[str, object] = {"database": "*", "table": "T", "columns": ["c"]}
    assert "wildcards are allowed only in pii rule table or database" in summary(
        dict(base, schema="s*")
    )
    assert "database must be an exact name or '*'" in summary(dict(base, database="a*"))
    assert "pii rule columns must be unique" in summary(dict(base, columns=["c", "C"]))


@pytest.mark.parametrize(
    ("section", "columns", "message"),
    [
        ("rules", ["*"], "pii rules and exposed_columns cannot list '*' columns; only deny can"),
        (
            "exposed_columns",
            ["*"],
            "pii rules and exposed_columns cannot list '*' columns; only deny can",
        ),
        ("deny", ["a*"], "a deny column wildcard must be exactly ['*']"),
        ("deny", ["*", "b"], "a deny column wildcard must be exactly ['*']"),
    ],
    ids=["rules-star", "exposed-star", "deny-partial", "deny-star-and-name"],
)
def test_column_wildcards_are_reported_per_section(
    section: str, columns: list[str], message: str
) -> None:
    rule: dict[str, object] = {"database": "*", "table": "T", "columns": ["c"]}
    pii: dict[str, object] = {"rules": [rule]}
    pii[section] = [dict(rule, columns=columns)]

    assert message in _pii_summary(pii)


def test_table_patterns_are_valid_pii_rule_configuration() -> None:
    model = _model(base64.b64encode(bytes(range(32))).decode())
    server = cast(dict[str, object], model["servers"])["s"]
    assert isinstance(server, dict)
    server["pii"] = {
        "rules": [
            {"database": "*", "table": pattern, "columns": ["c"]}
            for pattern in ("T*", "T?", "T[abc]", "T[a-z]", "T[!abc]", "T[*]", "T[[]", "T[]]")
        ]
    }

    config = AppConfig.model_validate(model)

    pii = config.servers["s"].pii
    assert pii is not None
    assert [rule.table for rule in pii.rules] == [
        "T*",
        "T?",
        "T[abc]",
        "T[a-z]",
        "T[!abc]",
        "T[*]",
        "T[[]",
        "T[]]",
    ]


def test_non_ascii_values_survive_loading(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    url = "mssql+pyodbc://u:päss中@sql/master?driver=x"
    path.write_bytes(_yaml(url).encode("utf-8"))
    config = load_config(path, {})
    assert config.servers["s"].connection_url.get_secret_value() == url


def test_root_level_validation_errors_have_no_location_prefix(tmp_path: Path) -> None:
    text = _yaml().replace("  s:\n", "  _bad:\n")
    error = _error(_write(tmp_path, text))
    assert error.public_message == (
        "Invalid configuration: Value error, invalid server alias '_bad'"
    )
