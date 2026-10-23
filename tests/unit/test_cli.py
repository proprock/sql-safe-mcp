from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest

import sql_safe_mcp.__main__ as cli
from sql_safe_mcp.pii_audit import Catalog, CatalogError


def _write_config(path: Path, *, extra: str = "") -> Path:
    path.write_text(
        f"""
version: 1
servers:
  legacy:
    engine: sqlserver
    connection_url: mssql+pyodbc://user:password@host/master?driver=x
    {extra}
""",
        encoding="utf-8",
    )
    return path


def _run(
    *arguments: str, environment: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sql_safe_mcp", *arguments],
        capture_output=True,
        check=False,
        text=True,
        env=environment,
    )


def test_check_config_returns_zero_for_explicit_path(tmp_path: Path) -> None:
    config = _write_config(tmp_path / "valid.yaml")

    result = _run("--config", str(config), "--check-config")

    assert result.returncode == 0
    assert result.stdout == "Configuration valid: 1 server alias(es).\n"
    assert result.stderr == ""


def test_check_config_uses_environment_path(tmp_path: Path) -> None:
    config = _write_config(tmp_path / "from-environment.yaml")
    environment = os.environ.copy()
    environment["SQL_SAFE_MCP_CONFIG"] = str(config)

    result = _run("--check-config", environment=environment)

    assert result.returncode == 0
    assert "Configuration valid" in result.stdout


def test_gen_pii_key_prints_one_valid_key_without_loading_configuration() -> None:
    result = _run("--gen-pii-key")

    assert result.returncode == 0
    assert result.stderr == ""
    keys = result.stdout.splitlines()
    assert len(keys) == 1
    assert len(base64.b64decode(keys[0], validate=True)) == 32


def test_gen_pii_key_prints_the_requested_number_of_distinct_keys() -> None:
    result = _run("--gen-pii-key", "3")

    assert result.returncode == 0
    assert result.stderr == ""
    keys = result.stdout.splitlines()
    assert len(keys) == 3
    assert len(set(keys)) == 3
    assert all(len(base64.b64decode(key, validate=True)) == 32 for key in keys)


def test_gen_pii_key_rejects_non_positive_count() -> None:
    result = _run("--gen-pii-key", "0")

    assert result.returncode == 2
    assert "positive integer" in result.stderr


def test_invalid_config_returns_two_without_traceback_or_secret(tmp_path: Path) -> None:
    secret = "cli-secret-value"
    config = _write_config(tmp_path / "invalid.yaml", extra=f"unknown: {secret}")

    result = _run("--config", str(config), "--check-config")

    assert result.returncode == 2
    assert "[CONFIG_ERROR]" in result.stderr
    assert "Traceback" not in result.stderr
    assert secret not in result.stderr
    assert "password" not in result.stderr


def test_malformed_connection_url_returns_two_without_traceback_or_secret(tmp_path: Path) -> None:
    secret = "cli-url-secret-marker"
    config = tmp_path / "malformed-url.yaml"
    config.write_text(
        f"""
version: 1
servers:
  legacy:
    engine: sqlserver
    connection_url: 'not a URL {secret}'
""",
        encoding="utf-8",
    )

    result = _run("--config", str(config), "--check-config")

    assert result.returncode == 2
    assert "[CONFIG_ERROR]" in result.stderr
    assert "Traceback" not in result.stderr
    assert secret not in result.stderr


_PII_CONFIG = """
version: 1
servers:
  clinic:
    engine: mysql
    access_level: all_pii_safe
    connection_url: mysql+pymysql://user:cli-pass-marker@host/clinic
    pii_key_env: CLINIC_KEY
    pii:
      rules:
        - {{database: clinic, table: patients, columns: [{column}]}}
"""


def _run_verify(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    *,
    column: str,
    strict: bool,
    catalog: Catalog,
) -> tuple[int, str]:
    config = tmp_path / "pii.yaml"
    config.write_text(_PII_CONFIG.format(column=column), encoding="utf-8")
    monkeypatch.setenv("CLINIC_KEY", base64.b64encode(b"k" * 32).decode("ascii"))
    monkeypatch.setattr(cli, "collect_catalog", lambda _config, _alias: catalog)
    argv = ["sql_safe_mcp", "--config", str(config), "--verify-pii-rules"]
    monkeypatch.setattr(sys, "argv", [*argv, *(["--strict"] if strict else [])])
    code = 0
    try:
        cli.main()
    except SystemExit as exit_:
        code = int(exit_.code or 0)
    return code, capsys.readouterr().err


_CATALOG: Catalog = {"clinic": [(None, "patients", ("id", "email", "Emial", "visit_notes"))]}


def test_verify_pii_rules_warns_about_unmatched_rule_and_fails_when_strict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, err = _run_verify(
        monkeypatch, capsys, tmp_path, column="emial2", strict=True, catalog=_CATALOG
    )

    assert code == 2
    assert "WARNING: clinic: rule clinic.patients(emial2) matches no table or column" in err


def test_verify_pii_rules_unmatched_rule_passes_without_strict(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, err = _run_verify(
        monkeypatch, capsys, tmp_path, column="emial2", strict=False, catalog=_CATALOG
    )

    assert code == 0
    assert "matches no table or column" in err


def test_verify_pii_rules_matching_rule_returns_zero_and_advises_on_open_columns(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, err = _run_verify(
        monkeypatch, capsys, tmp_path, column="email", strict=True, catalog=_CATALOG
    )

    assert code == 0
    assert "rule clinic.patients(email) matched 1 table(s), 1 column(s)" in err
    assert "unprotected column looks personal: clinic.patients.visit_notes" in err
    # The advisor is a fixed dictionary: it does not catch the misspelled "Emial".
    assert "clinic.patients.Emial" not in err
    assert "clinic.patients.email" not in err
    assert "cli-pass-marker" not in err


def test_verify_pii_rules_connection_failure_returns_two_without_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def fail(_config: object, _alias: str) -> object:
        raise CatalogError("cannot reflect database 'clinic': OperationalError code=2003")

    config = tmp_path / "pii.yaml"
    config.write_text(_PII_CONFIG.format(column="email"), encoding="utf-8")
    monkeypatch.setenv("CLINIC_KEY", base64.b64encode(b"k" * 32).decode("ascii"))
    monkeypatch.setattr(cli, "collect_catalog", fail)
    monkeypatch.setattr(
        sys, "argv", ["sql_safe_mcp", "--config", str(config), "--verify-pii-rules"]
    )

    with pytest.raises(SystemExit) as raised:
        cli.main()

    err = capsys.readouterr().err
    assert raised.value.code == 2
    assert "ERROR: clinic: cannot reflect database" in err
    assert "cli-pass-marker" not in err


def test_strict_requires_verify_pii_rules() -> None:
    result = _run("--strict")

    assert result.returncode == 2
    assert "--strict requires --verify-pii-rules" in result.stderr
