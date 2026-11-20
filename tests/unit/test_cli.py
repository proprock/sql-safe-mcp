from __future__ import annotations

import base64
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
import yaml

import sql_safe_mcp.__main__ as cli
from sql_safe_mcp.config import PiiConfig
from sql_safe_mcp.pii_audit import Catalog, CatalogError
from sql_safe_mcp.pii_scaffold import ScaffoldCatalog, ScaffoldColumn


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


def test_check_config_reads_a_generated_key_file(tmp_path: Path) -> None:
    key_file = tmp_path / "secrets" / "clinic.key"
    key_file.parent.mkdir()
    key_file.write_text(_run("--gen-pii-key").stdout, encoding="ascii")
    key_file.chmod(0o600)
    config = tmp_path / "pii.yaml"
    config.write_text(
        _PII_CONFIG.format(column="email").replace(
            "pii_key_env: CLINIC_KEY", "pii_key_file: secrets/clinic.key"
        ),
        encoding="utf-8",
    )

    result = _run("--config", str(config), "--check-config")

    assert result.stderr == ""
    assert result.stdout == "Configuration valid: 1 server alias(es).\n"


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
    connection_url: mysql+pymysql://user:cli-pass-marker@host/clinic?ssl_ca=/ca.pem
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


# --- --scaffold-pii ---------------------------------------------------------------------------

_SCAFFOLD_CATALOG = ScaffoldCatalog(
    databases={
        "clinic": [
            (
                None,
                "patients",
                (
                    ScaffoldColumn("id", "integer", True),
                    ScaffoldColumn("email", "string", False),
                    ScaffoldColumn("visits", "integer", False),
                ),
            )
        ]
    },
    visible=1,
)


def _run_scaffold(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    *arguments: str,
    collect: object = None,
    config_text: str | None = None,
) -> tuple[int, str, str, list[tuple[str, tuple[str, ...]]]]:
    config = tmp_path / "pii.yaml"
    config.write_text(config_text or _PII_CONFIG.format(column="email"), encoding="utf-8")
    monkeypatch.setenv("CLINIC_KEY", base64.b64encode(b"k" * 32).decode("ascii"))
    calls: list[tuple[str, tuple[str, ...]]] = []

    def default(_config: object, alias: str, databases: Sequence[str]) -> ScaffoldCatalog:
        calls.append((alias, tuple(databases)))
        return _SCAFFOLD_CATALOG

    monkeypatch.setattr(cli, "collect_scaffold_catalog", collect or default)
    monkeypatch.setattr(sys, "argv", ["sql_safe_mcp", "--config", str(config), *arguments])
    code = 0
    try:
        cli.main()
    except SystemExit as exit_:
        code = int(exit_.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err, calls


def test_scaffold_pii_prints_a_valid_draft_to_stdout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, out, err, calls = _run_scaffold(monkeypatch, capsys, tmp_path, "--scaffold-pii", "clinic")

    assert code == 0
    assert calls == [("clinic", ())]
    draft = yaml.safe_load(out)
    PiiConfig.model_validate(draft)
    assert draft["exposed_columns"] == [{"table": "patients", "columns": ["visits"]}]
    assert "Reflected 1 database(s), 1 table(s)." in err
    assert "cli-pass-marker" not in out + err


def test_scaffold_pii_passes_every_database_option(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, _, _, calls = _run_scaffold(
        monkeypatch,
        capsys,
        tmp_path,
        "--scaffold-pii",
        "clinic",
        "--database",
        "b",
        "--database",
        "a",
    )

    assert code == 0
    assert calls == [("clinic", ("b", "a"))]


def test_scaffold_pii_unknown_alias_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    code, out, err, calls = _run_scaffold(
        monkeypatch, capsys, tmp_path, "--scaffold-pii", "nope\nERROR: forged"
    )

    assert code == 2
    assert out == ""
    assert "ERROR: unknown server alias 'nope?ERROR??forged'" in err
    assert calls == []


def test_scaffold_pii_metadata_alias_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    metadata = """
version: 1
servers:
  plain:
    engine: mysql
    access_level: metadata
    connection_url: mysql+pymysql://user:cli-pass-marker@host/clinic?ssl_ca=/ca.pem
"""
    code, out, err, calls = _run_scaffold(
        monkeypatch, capsys, tmp_path, "--scaffold-pii", "plain", config_text=metadata
    )

    assert code == 2
    assert out == ""
    assert "ERROR: plain: access_level is metadata" in err
    assert calls == []


def test_scaffold_pii_connection_failure_exits_two_without_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def fail(_config: object, _alias: str, _databases: object) -> object:
        raise CatalogError("cannot reflect database 'clinic': OperationalError code=2003")

    code, out, err, _ = _run_scaffold(
        monkeypatch, capsys, tmp_path, "--scaffold-pii", "clinic", collect=fail
    )

    assert code == 2
    assert out == ""
    assert "ERROR: clinic: cannot reflect database" in err
    assert "cli-pass-marker" not in err


def test_scaffold_pii_with_no_tables_exits_two_not_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    def empty(_config: object, _alias: str, _databases: object) -> ScaffoldCatalog:
        return ScaffoldCatalog(databases={"clinic": []}, visible=1)

    code, out, err, _ = _run_scaffold(
        monkeypatch, capsys, tmp_path, "--scaffold-pii", "clinic", collect=empty
    )

    assert code == 2
    assert out == ""
    assert "no tables reflected; check the database names and the login's metadata" in err


def test_database_requires_scaffold_pii() -> None:
    result = _run("--database", "x")

    assert result.returncode == 2
    assert "--database requires --scaffold-pii" in result.stderr


def test_strict_is_rejected_with_scaffold_pii() -> None:
    result = _run("--scaffold-pii", "clinic", "--strict")

    assert result.returncode == 2
    assert "--strict requires --verify-pii-rules" in result.stderr


def test_scaffold_pii_is_exclusive_with_the_other_actions() -> None:
    result = _run("--scaffold-pii", "clinic", "--verify-pii-rules")

    assert result.returncode == 2
    assert "not allowed with argument" in result.stderr
