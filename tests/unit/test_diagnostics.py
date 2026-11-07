from __future__ import annotations

import logging

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from sql_safe_mcp.diagnostics import configure_logging, describe_error, secrets_for


class _OdbcError(Exception):
    """Shaped like pyodbc.Error: args are (sqlstate, message)."""


class _MySqlError(Exception):
    """Shaped like pymysql errors: args are (code, message)."""


def _wrapped(orig: Exception) -> OperationalError:
    return OperationalError("SELECT 1", None, orig)


def test_secrets_for_maps_credentials_to_stars_and_host_to_the_alias() -> None:
    redactions = dict(secrets_for("mssql+pyodbc://a%40b:p%3A%2Fx@sql01/master?driver=x", "legacy"))

    assert redactions == {
        "a@b": "***",
        "a%40b": "***",
        "p:/x": "***",
        "p%3A%2Fx": "***",
        "sql01": "legacy",
    }


def test_secrets_for_ignores_missing_parts_and_unparsable_urls() -> None:
    assert secrets_for("mysql+pymysql://db.internal/shop", "shop") == (("db.internal", "shop"),)
    assert secrets_for("not a url", "shop") == ()


def test_describe_error_reports_class_sqlstate_and_message() -> None:
    error = _wrapped(_OdbcError("HYT00", "[HYT00] Login timeout expired"))

    assert describe_error(error, ()) == (
        "_OdbcError sqlstate=HYT00 message=[HYT00] Login timeout expired"
    )


def test_describe_error_reports_numeric_driver_code() -> None:
    error = _wrapped(_MySqlError(1045, "Access denied for user"))

    assert describe_error(error, ()) == "_MySqlError code=1045 message=Access denied for user"


def test_describe_error_falls_back_to_the_exception_text() -> None:
    assert describe_error(RuntimeError("boom"), ()) == "RuntimeError message=boom"


def test_describe_error_redacts_secrets() -> None:
    secrets = secrets_for("mssql+pyodbc://svc_app:S3cr3t!@sql01.corp/master?driver=x", "legacy")
    error = _wrapped(
        _OdbcError("28000", "Login failed for user 'svc_app' on SQL01.corp, pwd S3cr3t!")
    )

    line = describe_error(error, secrets)

    for secret in ("svc_app", "S3cr3t!", "sql01.corp"):
        assert secret.casefold() not in line.casefold()
    assert "Login failed for user '***' on legacy, pwd ***" in line


def test_describe_error_redacts_short_usernames_only_as_whole_words() -> None:
    error = _wrapped(_OdbcError("28000", "Login failed for user 'sa'. Password rejected."))

    line = describe_error(error, (("sa", "***"),))

    assert "'sa'" not in line
    assert "Password rejected" in line


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Conversion failed for value 'john@x.com'", "Conversion failed for value '***'"),
        ("Invalid value N'john@x.com' here", "Invalid value N'***' here"),
        ('Bad value "john@x.com" here', 'Bad value "***" here'),
        ("Duplicate entry 'a@x.com' for key 'email' ", "Duplicate entry '***' for key '***'"),
        ("Cannot convert 1234567890 to int", "Cannot convert *** to int"),
        ("Cannot convert 12345 to int", "Cannot convert 12345 to int"),
        ("Value 'it''s' bad", "Value '***''***' bad"),
    ],
)
def test_describe_error_redacts_quoted_literals_and_long_digit_runs(
    message: str, expected: str
) -> None:
    assert describe_error(RuntimeError(message), ()) == f"RuntimeError message={expected}"


@pytest.mark.parametrize(
    ("secret", "message", "expected"),
    [
        ("sa", "visa sa", "visa ***"),
        ("sa", "sa-x", "***-x"),
        ("!pw9", "x!pw9 y", "x*** y"),
        ("pw9!", "y pw9!x", "y ***x"),
        ("!pw9!", "a!pw9!b", "a***b"),
    ],
    ids=["word-edge-in-word", "word-edge-before-dash", "punct-start", "punct-end", "punct-both"],
)
def test_describe_error_bounds_only_word_character_edges_of_a_secret(
    secret: str, message: str, expected: str
) -> None:
    line = describe_error(RuntimeError(message), ((secret, "***"),))

    assert line == f"RuntimeError message={expected}"


def test_describe_error_can_omit_the_message() -> None:
    error = _wrapped(_OdbcError("22018", "Conversion failed for value 'john@x.com'"))

    line = describe_error(error, (), include_message=False)

    assert line == "_OdbcError sqlstate=22018"


def test_describe_error_removes_control_characters_and_truncates() -> None:
    forged = "first\r\nINFO forged log line\x1b[0m" + "x" * 1000

    line = describe_error(RuntimeError(forged), ())

    assert "\n" not in line
    assert "\r" not in line
    assert "\x1b" not in line
    assert len(line) < 600
    assert line.endswith("...")


def test_describe_error_redacts_the_longest_secret_first() -> None:
    message = "connect a.b.c failed"
    redactions = (("b.c", "short"), ("a.b.c", "***"))

    assert describe_error(RuntimeError(message), redactions) == (
        "RuntimeError message=connect *** failed"
    )


def test_describe_error_replaces_each_control_run_with_one_space() -> None:
    assert describe_error(RuntimeError("a\r\n\x00b"), ()) == "RuntimeError message=a b"


def test_describe_error_truncates_only_beyond_the_limit() -> None:
    at_limit = "x" * 500

    assert describe_error(RuntimeError(at_limit), ()) == f"RuntimeError message={at_limit}"
    assert describe_error(RuntimeError(at_limit + "y"), ()) == (
        f"RuntimeError message={at_limit}..."
    )


def test_configure_logging_sets_package_level_and_pins_sqlalchemy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    configure_logging("DEBUG")

    assert logging.getLogger("sql_safe_mcp").level == logging.DEBUG
    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        connection.execute(text("SELECT :value"), {"value": "pii-plaintext"})
    engine.dispose()
    assert not [record for record in caplog.records if record.name.startswith("sqlalchemy")]
    assert "pii-plaintext" not in caplog.text


def test_configure_logging_holds_only_the_sqlalchemy_logger_at_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sqlalchemy_logger = logging.getLogger("sqlalchemy")
    root = logging.getLogger()
    # Earlier calls in the same process leave the level set; start from a clean slate.
    monkeypatch.setattr(sqlalchemy_logger, "level", logging.NOTSET)
    monkeypatch.setattr(root, "level", logging.INFO)

    configure_logging("DEBUG")

    assert sqlalchemy_logger.level == logging.WARNING
    assert root.level == logging.INFO


def test_configure_logging_keeps_the_audit_trail_below_a_quiet_package_level() -> None:
    audit = logging.getLogger("sql_safe_mcp.audit")

    configure_logging("ERROR", audit=True)
    assert audit.isEnabledFor(logging.INFO)

    configure_logging("ERROR")
    assert not audit.isEnabledFor(logging.INFO)
    configure_logging("INFO")
