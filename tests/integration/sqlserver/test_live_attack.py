"""Milestone 2B live attack gate: hostile SQL against a really writable SQL Server login."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest
from attack_lab import FORBIDDEN_ON_THE_WIRE, AttackLab
from corpus_support import TokenSources, expand, load_cases

from sql_safe_mcp.config import AppConfig
from sql_safe_mcp.db.registry import EngineRegistry
from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.models import SqlResult
from sql_safe_mcp.security.tokens import TokenCodec
from sql_safe_mcp.service import DatabaseService

pytestmark = pytest.mark.integration


def run(lab: AttackLab, sql: str, alias: str = "attack", database: int = 0, **extra: Any):
    return asyncio.run(lab.service.execute_sql(alias, lab.databases[database], sql, **extra))


def error_of(lab: AttackLab, sql: str, alias: str = "attack", database: int = 0) -> DomainError:
    with pytest.raises(DomainError) as info:
        run(lab, sql, alias, database)
    return info.value


def codec(lab: AttackLab, alias: str = "attack") -> TokenCodec:
    return TokenCodec(alias, lab.keys[alias])


def token(lab: AttackLab, value: str, alias: str = "attack") -> str:
    return codec(lab, alias).encrypt(value)


def digest(state: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()


def write_artifact(name: str, payload: dict[str, Any]) -> None:
    """Attach audit evidence for the review when SQL_SAFE_MCP_AUDIT_DIR is set."""
    directory = os.environ.get("SQL_SAFE_MCP_AUDIT_DIR")
    if not directory:
        return
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    (target / f"{name}.json").write_text(json.dumps(payload, indent=2, default=str), "utf-8")


def test_the_credential_is_really_writable(attack_lab: AttackLab) -> None:
    """Positive control: without it, an unchanged canary would prove nothing."""
    before = digest(attack_lab.snapshot())
    for database in attack_lab.databases:
        engine = attack_lab.writer_engine(database)
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql("INSERT INTO dbo.[Canary] VALUES (999, N'control')")
                connection.exec_driver_sql("UPDATE dbo.[Canary] SET Note = N'x' WHERE Id = 999")
                connection.exec_driver_sql("DELETE FROM dbo.[Canary] WHERE Id = 999")
                connection.exec_driver_sql("CREATE TABLE dbo.[ControlTable] (Id int)")
                connection.exec_driver_sql("DROP TABLE dbo.[ControlTable]")
        finally:
            engine.dispose()
    assert digest(attack_lab.snapshot()) == before


def test_corpus_neither_reaches_the_driver_nor_changes_anything(attack_lab: AttackLab) -> None:
    lab = attack_lab
    tokens = TokenSources(
        codec(lab), codec(lab, "attack2"), TokenCodec("attack", lab.keys["attack2"])
    )
    before = lab.snapshot()
    mark = lab.recorder.mark()
    cases = load_cases()
    mismatches: list[str] = []
    for case_id, case in cases:
        expected = ErrorCode(case.get("code", "QUERY_REJECTED"))
        try:
            run(lab, expand(case["sql"], tokens))
        except DomainError as error:
            if error.code is not expected:
                mismatches.append(f"{case_id}: {error.code} != {expected}")
        else:
            mismatches.append(f"{case_id}: was accepted")
    after = lab.snapshot()
    statements = lab.recorder.since(mark)

    offenders = [
        statement
        for statement, _ in statements
        if statement.lstrip().upper().startswith("SELECT TOP")
        or any(word in statement.upper() for word in FORBIDDEN_ON_THE_WIRE)
    ]
    write_artifact(
        "corpus-run",
        {
            "cases": len(cases),
            "mismatches": mismatches,
            "driver_statements": len(statements),
            "distinct_driver_statements": sorted({s[:160] for s, _ in statements}),
            "snapshot_before": digest(before),
            "snapshot_after": digest(after),
            "canary_before": before[lab.databases[0]]["Canary"],
            "canary_after": after[lab.databases[0]]["Canary"],
            "offending_statements": offenders,
        },
    )
    assert mismatches == []
    assert offenders == []
    assert digest(after) == digest(before)
    assert after == before


def test_accepted_queries_send_generated_sql_with_bound_values(attack_lab: AttackLab) -> None:
    lab = attack_lab
    before = digest(lab.snapshot())
    payload = "x'; DROP TABLE Canary;--"
    cases = [
        (f"SELECT Id FROM Users WHERE Email = '{token(lab, payload)}'", (payload,)),
        (
            "SELECT Id FROM Users WHERE Email IN "
            f"('{token(lab, 'bind-alpha')}', '{token(lab, 'bind-beta')}')",
            ("bind-alpha", "bind-beta"),
        ),
        ("SELECT Id FROM Users WHERE Name = 'it''s :pii_0 ?'", ()),
    ]
    recorded = []
    for sql, expected_binds in cases:
        mark = lab.recorder.mark()
        run(lab, sql)
        sent = [(s, p) for s, p in lab.recorder.since(mark) if s.startswith("SELECT TOP")]
        assert len(sent) == 1, sent
        statement, params = sent[0]
        assert tuple(params) == expected_binds
        assert statement.count("?") >= len(expected_binds)
        for value in expected_binds:
            assert value not in statement
        assert "pii:v1" not in statement
        assert "DROP" not in statement.upper() or ("DROP" in sql.upper() and not expected_binds)
        recorded.append({"sql_sent": statement, "binds": list(params)})
    write_artifact("accepted-queries", {"queries": recorded})
    assert digest(lab.snapshot()) == before


def test_pii_markers_never_appear_in_responses_logs_errors_or_statements(
    attack_lab: AttackLab, caplog: pytest.LogCaptureFixture
) -> None:
    lab = attack_lab
    mark = lab.recorder.mark()
    outputs: list[str] = []
    with caplog.at_level(logging.DEBUG):
        for sql in (
            "SELECT * FROM Users",
            "SELECT Email, Phone FROM Users ORDER BY Id",
            "SELECT u.Email FROM Users u JOIN Orders o ON o.UserId = u.Id",
            f"SELECT Id FROM Users WHERE Email = '{token(lab, lab.markers[0])}'",
        ):
            result = run(lab, sql)
            outputs.append(result.model_dump_json())
        for marker in lab.markers:
            for sql in (
                f"SELECT Id FROM Users WHERE Email = '{marker}'",
                f"SELECT Id FROM Users WHERE Phone IN ('{marker}')",
                f"SELECT Id FROM Users WHERE Email = 'pii:v1:{marker}'",
                f"SELECT Id FROM Users WHERE Name = '{marker}' AND Email = '{marker}'",
            ):
                outputs.append(str(error_of(lab, sql)))
    corpus = "\n".join(outputs) + caplog.text
    statements = "\n".join(statement for statement, _ in lab.recorder.since(mark))
    leaks = [m for m in lab.markers if m in corpus or m in statements]
    write_artifact(
        "marker-scan",
        {"markers": len(lab.markers), "leaks": leaks, "scanned_chars": len(corpus)},
    )
    assert leaks == []


def test_malformed_wrong_key_and_wrong_alias_tokens_are_indistinguishable(
    attack_lab: AttackLab,
) -> None:
    lab = attack_lab
    valid = token(lab, "value")
    flipped = valid[:-2] + ("A" if valid[-2] != "A" else "B") + valid[-1]
    variants = {
        "malformed": "pii:v1:AAAA",
        "truncated": valid[:-10],
        "flipped": flipped,
        "wrong alias": token(lab, "value", "attack2"),
        "wrong key same alias": TokenCodec("attack", lab.keys["attack2"]).encrypt("value"),
        "padded": valid + "=",
    }
    seen = {}
    for name, bad in variants.items():
        error = error_of(lab, f"SELECT Id FROM Users WHERE Email = '{bad}'")
        assert error.code is ErrorCode.INVALID_PII_TOKEN, name
        seen[name] = (error.code, error.public_message, error.hint, error.retryable)
        assert error.correlation_id is None
    assert len(set(seen.values())) == 1
    write_artifact("token-errors", {name: list(map(str, item)) for name, item in seen.items()})


def test_tokens_work_between_databases_of_one_alias_but_not_between_aliases(
    attack_lab: AttackLab,
) -> None:
    lab = attack_lab
    issued = run(lab, "SELECT Email FROM Users WHERE Id = 1", database=0)
    minted = issued.rows[0][0]
    same_alias_other_db = run(lab, f"SELECT Id FROM Users WHERE Email = '{minted}'", database=1)
    assert same_alias_other_db.row_count == 1
    other_alias = error_of(lab, f"SELECT Id FROM Users WHERE Email = '{minted}'", alias="attack2")
    assert other_alias.code is ErrorCode.INVALID_PII_TOKEN
    reverse = run(lab, "SELECT Email FROM Users WHERE Id = 1", alias="attack2")
    error = error_of(lab, f"SELECT Id FROM Users WHERE Email = '{reverse.rows[0][0]}'")
    assert error.code is ErrorCode.INVALID_PII_TOKEN


def test_a_test_only_alias_with_the_same_key_still_rejects_the_token(attack_lab: AttackLab) -> None:
    """Config forbids shared keys, so build the clone by hand; only the AAD alias differs."""
    lab = attack_lab
    original = lab.config.servers["attack"]
    clone = original.model_copy()
    servers = {"attack": original, "attack-clone": clone}
    config = AppConfig.model_construct(version=1, runtime=lab.config.runtime, servers=servers)
    registry = EngineRegistry(config)
    try:
        service = DatabaseService(config, registry)
        minted = run(lab, "SELECT Email FROM Users WHERE Id = 1").rows[0][0]
        with pytest.raises(DomainError) as info:
            asyncio.run(
                service.execute_sql(
                    "attack-clone",
                    lab.databases[0],
                    f"SELECT Id FROM Users WHERE Email = '{minted}'",
                )
            )
        assert info.value.code is ErrorCode.INVALID_PII_TOKEN
        again = asyncio.run(
            service.execute_sql(
                "attack",
                lab.databases[0],
                f"SELECT Id FROM Users WHERE Email = '{minted}'",
            )
        )
        assert isinstance(again, SqlResult)
        assert again.row_count == 1
    finally:
        registry.dispose()


def test_a_string_token_against_an_int_column_is_rejected_before_the_database(
    attack_lab: AttackLab, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    """Before the type check SQL Server answered with error 245 that echoed the value."""
    lab = attack_lab
    value = "424242"
    mark = lab.recorder.mark()
    with caplog.at_level(logging.DEBUG):
        error = error_of(lab, f"SELECT Id FROM Visits WHERE Hits = '{token(lab, value)}'")
        listed = error_of(lab, f"SELECT Id FROM Visits WHERE Hits IN ('{token(lab, value)}')")
    assert error.code is ErrorCode.QUERY_REJECTED
    assert listed.code is ErrorCode.QUERY_REJECTED
    # Reflection queries may reach the driver; the user's predicate must not.
    sent = [statement for statement, _ in lab.recorder.since(mark)]
    assert not [statement for statement in sent if "[Hits]" in statement and "WHERE" in statement]
    captured = capfd.readouterr()
    for text in (str(error), str(listed), caplog.text, captured.out, captured.err):
        assert value not in text


def test_aliased_expressions_over_a_protected_column_never_reach_the_driver(
    attack_lab: AttackLab, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    """Audit finding C1: an aliased expression once projected a protected column in clear."""
    lab = attack_lab
    marker = lab.markers[0]
    mark = lab.recorder.mark()
    with caplog.at_level(logging.DEBUG):
        errors = {
            sql: error_of(lab, sql)
            for sql in (
                "SELECT (Email) AS e FROM Users",
                "SELECT ((Email)) AS e FROM Users ORDER BY Id",
                f"SELECT (Email = '{marker}') AS hit FROM Users",
                "SELECT u.Id, (u.Phone) AS p FROM Users u",
            )
        }
    sent = [statement for statement, _ in lab.recorder.since(mark)]
    captured = capfd.readouterr()
    texts = [str(error) for error in errors.values()]
    texts += [caplog.text, captured.out, captured.err, *sent]
    leaks = [m for m in lab.markers if any(m in text for text in texts)]
    write_artifact(
        "aliased-expressions",
        {"codes": sorted({e.code.value for e in errors.values()}), "leaks": leaks},
    )
    assert {error.code for error in errors.values()} == {ErrorCode.QUERY_REJECTED}
    assert not [s for s in sent if "[Users]" in s and ("[Email]" in s or "[Phone]" in s)]
    assert leaks == []


def test_an_int_token_against_an_int_column_runs(attack_lab: AttackLab) -> None:
    lab = attack_lab
    result = run(lab, f"SELECT Id FROM Visits WHERE Hits = '{codec(lab).encrypt(424242)}'")
    assert result.rows == [[1]]
