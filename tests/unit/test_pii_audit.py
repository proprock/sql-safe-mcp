from __future__ import annotations

import base64

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
