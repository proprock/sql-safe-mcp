from __future__ import annotations

import base64

import pytest

from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.pii_audit import Catalog, _database_names, audit_server

_CATALOG: Catalog = {
    "clinic": [
        (None, "visits", ("id", "department", "visit_notes", "email")),
        (None, "attachments", ("id", "photo")),
    ]
}


def _server(pii: dict[str, object]) -> AppConfig:
    return AppConfig.model_validate(
        {
            "version": 1,
            "servers": {
                "clinic": {
                    "engine": "mysql",
                    "access_level": "all_pii_safe",
                    "connection_url": "mysql+pymysql://u:p@host/clinic?ssl_ca=/ca.pem",
                    "pii_key_env": "K",
                    "pii_key": base64.b64encode(b"k" * 32).decode(),
                    "pii": pii,
                }
            },
        }
    )


def _audit(pii: dict[str, object]) -> tuple[str, int]:
    config = _server(pii)
    report = audit_server("clinic", config.servers["clinic"], _CATALOG)
    return "\n".join(report.lines), report.unmatched_rules


def test_deny_and_exposed_entries_are_reported_and_unmatched_ones_are_counted() -> None:
    text, unmatched = _audit(
        {
            "mode": "deny-by-default",
            "exposed_columns": [{"database": "clinic", "table": "visits", "columns": ["id"]}],
            "deny": [
                {"database": "clinic", "table": "visits", "columns": ["visit_notes"]},
                {"database": "clinic", "table": "visits", "columns": ["visit_notez"]},
            ],
        }
    )

    assert "clinic: exposed clinic.visits(id) matched 1 table(s), 1 column(s)" in text
    assert "clinic: deny clinic.visits(visit_notes) matched 1 table(s), 1 column(s)" in text
    assert "WARNING: clinic: deny clinic.visits(visit_notez) matches no table or column" in text
    assert unmatched == 1


def test_deny_wildcard_columns_match_every_column_of_the_table() -> None:
    text, unmatched = _audit(
        {"deny": [{"database": "clinic", "table": "attachments", "columns": ["*"]}]}
    )

    assert "deny clinic.attachments(*) matched 1 table(s), 2 column(s)" in text
    assert unmatched == 0


def test_denied_columns_are_not_advised_as_unprotected() -> None:
    text, _ = _audit(
        {
            "rules": [{"database": "clinic", "table": "visits", "columns": ["email"]}],
            "deny": [{"database": "clinic", "table": "visits", "columns": ["visit_notes"]}],
        }
    )

    assert "visit_notes" not in text.replace("deny clinic.visits(visit_notes)", "")
    assert "clinic.attachments.photo" in text


def test_deny_by_default_advises_only_on_exposed_columns() -> None:
    text, _ = _audit(
        {
            "mode": "deny-by-default",
            "exposed_columns": [
                {"database": "clinic", "table": "visits", "columns": ["id", "email"]}
            ],
        }
    )

    assert "unprotected column looks personal: clinic.visits.email" in text
    assert "clinic.visits.visit_notes" not in text
    assert "clinic.attachments.photo" not in text


def test_databases_of_exposed_and_deny_entries_are_reflected() -> None:
    config = _server(
        {
            "mode": "deny-by-default",
            "exposed_columns": [{"database": "a", "table": "t", "columns": ["x"]}],
            "deny": [{"table": "t", "columns": ["*"]}],
        }
    )
    pii = config.servers["clinic"].pii
    assert pii is not None

    assert _database_names([*pii.rules, *pii.exposed_columns, *pii.deny]) == ({"a"}, True)


SAFE_HARBOR_COLUMNS = [
    ("fax", "fax_number"),
    ("account", "account_no"),
    ("acct", "acct_id"),
    ("license", "license_no"),
    ("licence", "licence_no"),
    ("biometric", "biometric_id"),
    ("fingerprint", "fingerprint_hash"),
    ("insurance", "insurance_id"),
    ("policy", "policy_no"),
    ("member", "member_id"),
    ("street", "street_line"),
    ("county", "county_code"),
    ("admission", "admission_code"),
    ("admit", "admit_flag"),
    ("discharg", "discharge_code"),
    ("death", "death_code"),
    ("deceased", "deceased_flag"),
]


def _audit_columns(pii: dict[str, object], column: str) -> tuple[str, int, int]:
    catalog: Catalog = {"clinic": [(None, "t", ("id", column))]}
    report = audit_server("clinic", _server(pii).servers["clinic"], catalog)
    return "\n".join(report.lines), report.unmatched_rules, report.errors


@pytest.mark.parametrize(("fragment", "column"), SAFE_HARBOR_COLUMNS, ids=lambda v: v)
def test_safe_harbor_fragment_warns_for_an_unprotected_column(fragment: str, column: str) -> None:
    # A rule on another column keeps the config valid while the checked column stays unprotected.
    pii: dict[str, object] = {"rules": [{"database": "clinic", "table": "t", "columns": ["id"]}]}

    text, unmatched, errors = _audit_columns(pii, column)

    assert f"unprotected column looks personal: clinic.t.{column}" in text
    # A warning never changes the exit path: no unmatched rules and no errors.
    assert (unmatched, errors) == (0, 0)


@pytest.mark.parametrize(("fragment", "column"), SAFE_HARBOR_COLUMNS, ids=lambda v: v)
def test_safe_harbor_fragment_is_silent_for_a_protected_column(fragment: str, column: str) -> None:
    pii: dict[str, object] = {"rules": [{"database": "clinic", "table": "t", "columns": [column]}]}

    text, unmatched, errors = _audit_columns(pii, column)

    assert "looks personal" not in text
    assert (unmatched, errors) == (0, 0)


# Ordinary names that the advisory must stay quiet about. Each one contains a fragment that a
# bare-substring match would turn into noise (date, vin, url, city, plate, age).
BENIGN_COLUMNS = [
    "updated_at",
    "UpdateDate",
    "created_date",
    "validated",
    "template_id",
    "hourly_rate",
    "capacity",
    "savings",
    "driving_score",
    "province",
    "page",
    "message",
    "image",
]


@pytest.mark.parametrize("column", BENIGN_COLUMNS)
def test_ordinary_column_names_do_not_look_personal(column: str) -> None:
    pii: dict[str, object] = {"rules": [{"database": "clinic", "table": "t", "columns": ["id"]}]}

    text, _, _ = _audit_columns(pii, column)

    assert "looks personal" not in text


def test_a_star_exposed_entry_warns_that_it_opens_columns_added_later() -> None:
    text, unmatched = _audit(
        {
            "mode": "deny-by-default",
            "exposed_columns": [{"database": "clinic", "table": "[av]*", "columns": ["*"]}],
        }
    )

    assert "clinic: exposed clinic.[av]*(*) matched 2 table(s), 6 column(s)" in text
    assert (
        "WARNING: clinic: exposed clinic.[av]*(*) opens every column of 2 table(s), "
        "including columns added later"
    ) in text
    assert unmatched == 0


def test_a_star_exposed_entry_without_a_match_is_unmatched_and_has_no_opening_warning() -> None:
    text, unmatched = _audit(
        {
            "mode": "deny-by-default",
            "exposed_columns": [{"database": "clinic", "table": "Ref_*", "columns": ["*"]}],
        }
    )

    assert "WARNING: clinic: exposed clinic.Ref_*(*) matches no table or column" in text
    assert "opens every column" not in text
    assert unmatched == 1


def test_a_named_exposed_entry_and_a_star_deny_entry_do_not_warn_about_opening() -> None:
    text, _ = _audit(
        {
            "mode": "deny-by-default",
            "exposed_columns": [{"database": "clinic", "table": "visits", "columns": ["id"]}],
            "deny": [{"database": "clinic", "table": "attachments", "columns": ["*"]}],
        }
    )

    assert "opens every column" not in text


def test_the_name_advisor_still_checks_columns_opened_by_a_star_entry() -> None:
    text, _ = _audit(
        {
            "mode": "deny-by-default",
            "exposed_columns": [{"database": "clinic", "table": "visits", "columns": ["*"]}],
            "deny": [{"database": "clinic", "table": "visits", "columns": ["visit_notes"]}],
        }
    )

    assert "unprotected column looks personal: clinic.visits.email" in text
    assert "clinic.visits.visit_notes" not in text
    assert "clinic.attachments" not in text


def test_every_entry_that_matches_nothing_is_counted() -> None:
    _, unmatched = _audit(
        {
            "mode": "deny-by-default",
            "exposed_columns": [{"database": "clinic", "table": "Ref_*", "columns": ["*"]}],
            "deny": [{"database": "clinic", "table": "nothing", "columns": ["x"]}],
            "rules": [{"database": "clinic", "table": "none", "columns": ["y"]}],
        }
    )

    assert unmatched == 3
