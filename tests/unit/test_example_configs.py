"""Example configuration files in the repository root must load through the real loader."""

from __future__ import annotations

import base64
import re
from pathlib import Path

import pytest

from sql_safe_mcp.config import load_config

ROOT = Path(__file__).resolve().parents[2]
STRICT = "sql-safe-mcp.example-strict.yaml"
QA_OPEN = "sql-safe-mcp.example-qa-open.yaml"
MSSQL_URL = "mssql+pyodbc://u:p@sql/app?driver=x&Encrypt=yes"
MYSQL_URL = "mysql+pymysql://u:p@db/app?ssl_ca=/etc/ssl/ca.pem"
PLACEHOLDER = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
STRICT_KEY_PATH = "/run/secrets/main_pii_key"


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


# Each template that reads its key from an environment variable is paired with the environment it
# needs. Every ${NAME} placeholder in a file must appear here, so a new placeholder fails this test
# instead of being silently skipped.
TEMPLATE_ENV: dict[str, dict[str, str]] = {
    "sql-safe-mcp.example-simple.yaml": {"REPORTING_SQL_URL": MSSQL_URL},
    "sql-safe-mcp.example-multi.yaml": {
        "REPORTING_SQL_URL": MSSQL_URL,
        "BILLING_SQL_URL": MSSQL_URL,
        "BILLING_PII_KEY": _key(1),
        "SHOP_MYSQL_URL": MYSQL_URL,
        "SHOP_PII_KEY": _key(2),
    },
    "sql-safe-mcp.example-shared.yaml": {
        "LEGACY_PROD_USER": "u",
        "LEGACY_PROD_PASSWORD": "p",
        "LEGACY_PROD_HOST": "sql",
        "LEGACY_PROD_PII_KEY": _key(3),
        "PEDS_SQL_URL": MSSQL_URL,
        "PEDS_PII_KEY": _key(4),
        "REPORTING_SQL_URL": MSSQL_URL,
        "REPORTING_MYSQL_URL": MYSQL_URL,
    },
    QA_OPEN: {"QA_OPEN_SQL_URL": MSSQL_URL, "QA_OPEN_PII_KEY": _key(6)},
}


def _yaml_values(name: str) -> str:
    # Comments may mention ${NAME} as documentation; only YAML values are read from the environment.
    return "\n".join(
        line
        for line in (ROOT / name).read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith("#")
    )


def test_every_root_example_template_is_covered() -> None:
    on_disk = {path.name for path in ROOT.glob("sql-safe-mcp.example-*.yaml")}

    assert on_disk == {*TEMPLATE_ENV, STRICT}


@pytest.mark.parametrize("name", sorted(TEMPLATE_ENV))
def test_example_template_loads_through_load_config(name: str) -> None:
    missing = set(PLACEHOLDER.findall(_yaml_values(name))) - set(TEMPLATE_ENV[name])
    assert not missing, f"{name} uses placeholders the test does not set: {sorted(missing)}"

    config = load_config(ROOT / name, TEMPLATE_ENV[name])

    assert config.servers


def test_strict_template_is_one_policy_on_one_alias(tmp_path: Path) -> None:
    # The template reads its key from a secret file at a fixed path. The test writes a key file
    # and points a copy of the template at it, so the repository file itself stays unchanged.
    key_file = tmp_path / "main.key"
    key_file.write_text(_key(5), encoding="ascii")
    key_file.chmod(0o600)
    config_file = tmp_path / STRICT
    config_file.write_text(
        (ROOT / STRICT).read_text(encoding="utf-8").replace(STRICT_KEY_PATH, str(key_file)),
        encoding="utf-8",
    )
    missing = set(PLACEHOLDER.findall(_yaml_values(STRICT))) - {"MAIN_SQL_URL"}
    assert not missing, f"{STRICT} uses placeholders the test does not set: {sorted(missing)}"

    config = load_config(config_file, {"MAIN_SQL_URL": MSSQL_URL})

    assert set(config.servers) == {"main"}
    main = config.servers["main"]
    assert main.access_level == "all_pii_safe"
    assert main.pii is not None
    assert main.pii.mode == "deny-by-default"
    assert main.pii.exposed_columns
    assert main.pii.deny


def test_qa_open_template_is_a_separate_protect_only_alias() -> None:
    config = load_config(ROOT / QA_OPEN, TEMPLATE_ENV[QA_OPEN])

    assert set(config.servers) == {"qa_open"}
    qa_open = config.servers["qa_open"]
    assert qa_open.access_level == "all_pii_safe"
    assert qa_open.pii is not None
    assert qa_open.pii.mode == "protect"
    assert qa_open.pii.exposed_columns == []
    assert qa_open.pii.deny
