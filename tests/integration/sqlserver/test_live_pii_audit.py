from __future__ import annotations

import pytest
import yaml
from live_support import LiveDatabase

from sql_safe_mcp.config import AppConfig, PiiConfig, PiiRule
from sql_safe_mcp.pii_audit import collect_catalog, verify_pii_rules
from sql_safe_mcp.pii_scaffold import collect_scaffold_catalog, render_scaffold

pytestmark = pytest.mark.integration


def _with_rules(live: LiveDatabase, rules: list[PiiRule]) -> AppConfig:
    secure = live.config.servers["secure"].model_copy(update={"pii": PiiConfig(rules=rules)})
    return live.config.model_copy(update={"servers": {"secure": secure}})


def test_live_verify_reports_matched_and_unmatched_rules(live_database: LiveDatabase) -> None:
    live = live_database
    config = _with_rules(
        live,
        [
            PiiRule(
                database=live.database, schema=live.alpha_schema, table="Users", columns=["Email"]
            ),
            PiiRule(database="*", schema=live.alpha_schema, table="Users", columns=["Amount"]),
            PiiRule(
                database=live.database, schema=live.alpha_schema, table="Users", columns=["Emial"]
            ),
        ],
    )

    report = verify_pii_rules(config, collect_catalog)

    assert report.errors == 0
    assert report.unmatched_rules == 1
    text = "\n".join(report.lines)
    assert (
        f"{live.database}.{live.alpha_schema}.Users(Email) matched 1 table(s), 1 column(s)" in text
    )
    assert f"*.{live.alpha_schema}.Users(Amount) matched 1 table(s), 1 column(s)" in text
    assert f"{live.alpha_schema}.Users(Emial) matches no table or column" in text
    assert "password" not in text.casefold()


def test_live_verify_advises_on_unprotected_personal_looking_column(
    live_database: LiveDatabase,
) -> None:
    live = live_database
    config = _with_rules(
        live,
        [
            PiiRule(
                database=live.database, schema=live.alpha_schema, table="Users", columns=["Amount"]
            )
        ],
    )

    report = verify_pii_rules(config, collect_catalog)

    assert (
        f"unprotected column looks personal: {live.database}.{live.alpha_schema}.Users.Email"
        in "\n".join(report.lines)
    )


def test_live_verify_reports_unreachable_database_as_error(live_database: LiveDatabase) -> None:
    config = _with_rules(
        live_database,
        [PiiRule(database="smm_no_such_database", table="Users", columns=["Email"])],
    )

    report = verify_pii_rules(config, collect_catalog)

    assert report.errors == 1
    assert "ERROR: secure: cannot reflect database 'smm_no_such_database'" in "\n".join(
        report.lines
    )


def test_live_scaffold_drafts_a_section_that_passes_strict_verification(
    live_database: LiveDatabase,
) -> None:
    live = live_database
    config = _with_rules(
        live,
        [PiiRule(database="*", schema=live.alpha_schema, table="Users", columns=["Email"])],
    )

    pii = config.servers["secure"].pii
    assert pii is not None
    catalog = collect_scaffold_catalog(config, "secure", [live.database.upper()])
    text = render_scaffold("secure", catalog, pii)
    draft = yaml.safe_load(text)

    assert list(catalog.databases) == [live.database]
    exposed = {(e["schema"], e["table"]): set(e["columns"]) for e in draft["exposed_columns"]}
    denied = {(e["schema"], e["table"]): set(e["columns"]) for e in draft["deny"]}
    assert exposed[(live.alpha_schema, "Users")] == {"Amount"}
    assert {"F", "Flag"} <= exposed[(live.alpha_schema, "Kinds")]
    assert denied[(live.alpha_schema, "Kinds")] == {"B"}
    assert f"# protected by an existing rule: {live.alpha_schema}.Users.Email" in text
    pasted = config.servers["secure"].model_copy(update={"pii": PiiConfig.model_validate(draft)})
    report = verify_pii_rules(
        config.model_copy(update={"servers": {"secure": pasted}}), collect_catalog
    )
    assert report.errors == 0
    assert report.unmatched_rules == 0
