"""Configuration examples in the docs must load through the real configuration loader."""

from __future__ import annotations

import base64
import re
from pathlib import Path

from sql_safe_mcp.config import load_config

DOCS = Path(__file__).resolve().parents[2] / "docs"
KEY_FILE_IN_EXAMPLE = "/run/secrets/peds_pii_key"
EXAMPLE_ENV = {"PEDS_SQL_URL": "mssql+pyodbc://u:p@sql/peds?driver=x&Encrypt=yes"}


def _example_block(document: str) -> str:
    # Select the example by its key line, not by position, so a new YAML block elsewhere in the
    # document cannot silently replace the one under test.
    blocks = [
        block
        for block in re.findall(r"```yaml\n(.*?)```", document, re.S)
        if f"pii_key_file: {KEY_FILE_IN_EXAMPLE}" in block
    ]
    assert len(blocks) == 1, f"expected exactly one example block, found {len(blocks)}"
    return blocks[0]


def test_health_data_example_loads_through_load_config(tmp_path: Path) -> None:
    key_file = tmp_path / "peds.key"
    key_file.write_text(base64.b64encode(b"k" * 32).decode("ascii"), encoding="ascii")
    key_file.chmod(0o600)
    document = (DOCS / "health-data.md").read_text(encoding="utf-8")
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        _example_block(document).replace(KEY_FILE_IN_EXAMPLE, str(key_file)),
        encoding="utf-8",
    )

    config = load_config(config_file, EXAMPLE_ENV)

    server = config.servers["peds_ro"]
    assert server.access_level == "all_pii_safe"
    assert server.pii is not None
    assert server.pii.mode == "deny-by-default"
