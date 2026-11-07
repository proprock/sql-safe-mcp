from __future__ import annotations

import base64
import logging

import pytest
from pydantic import ValidationError

from sql_safe_mcp.config import AppConfig, ServerConfig
from sql_safe_mcp.mcp_server import create_server

_RULES = {"rules": [{"database": "*", "table": "T", "columns": ["c"]}]}
_MSSQL = "mssql+pyodbc://u:p@h/master?driver=x"
_MYSQL = "mysql+pymysql://u:p@h/app"
_TLS = "all_pii_safe servers require verified TLS: "


def _server(url: str, **extra: object) -> ServerConfig:
    engine = "sqlserver" if url.startswith("mssql") else "mysql"
    rules = (
        _RULES
        if engine == "sqlserver"
        else {"rules": [{"database": "app", "table": "T", "columns": ["c"]}]}
    )
    return ServerConfig.model_validate(
        {
            "engine": engine,
            "access_level": "all_pii_safe",
            "connection_url": url,
            "pii_key_env": "K",
            "pii": rules,
            **extra,
        }
    )


def _rejection(url: str, **extra: object) -> str:
    with pytest.raises(ValidationError) as info:
        _server(url, **extra)
    return str(info.value)


@pytest.mark.parametrize(
    "query",
    [
        "&Encrypt=yes",
        "&encrypt=TRUE",
        "&Encrypt=Mandatory",
        "&Encrypt=strict",
        "&Encrypt=yes&TrustServerCertificate=no",
        "&Encrypt=yes&trustservercertificate=False",
    ],
)
def test_sqlserver_with_verified_tls_is_accepted(query: str) -> None:
    assert _server(_MSSQL + query).require_tls is True


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("", "set Encrypt=yes in connection_url, or require_tls: false"),
        ("&Encrypt=no", "set Encrypt=yes in connection_url, or require_tls: false"),
        ("&Encrypt=optional", "set Encrypt=yes in connection_url, or require_tls: false"),
        (
            "&Encrypt=yes&TrustServerCertificate=yes",
            "connection_url option 'trustservercertificate' disables certificate checks; "
            "remove it, or set require_tls: false",
        ),
        (
            "&Encrypt=yes&TrustServerCertificate=maybe",
            "connection_url option 'trustservercertificate' disables certificate checks; "
            "remove it, or set require_tls: false",
        ),
        (
            "&Encrypt=yes&encrypt=no",
            "connection_url sets 'encrypt' more than once",
        ),
        (
            "&Encrypt=yes&Encrypt=yes",
            "connection_url sets 'encrypt' more than once",
        ),
        (
            "&odbc_connect=Encrypt%3Dyes",
            "odbc_connect cannot be checked; use URL query options, or set require_tls: false",
        ),
    ],
    ids=[
        "no-encrypt",
        "encrypt-no",
        "encrypt-optional",
        "trust-yes",
        "trust-unknown",
        "repeated-case",
        "repeated",
        "odbc-connect",
    ],
)
def test_sqlserver_without_verified_tls_is_rejected(query: str, message: str) -> None:
    assert f"Value error, {_TLS}{message} [type=value_error" in _rejection(_MSSQL + query)


@pytest.mark.parametrize(
    "query",
    ["?ssl_ca=/ca.pem", "?ssl_capath=/certs", "?ssl_ca=/ca.pem&ssl_check_hostname=true"],
)
def test_mysql_with_verified_tls_is_accepted(query: str) -> None:
    assert _server(_MYSQL + query).require_tls is True


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("", "set ssl_ca or ssl_capath in connection_url, or require_tls: false"),
        ("?ssl_cert=/c.pem", "set ssl_ca or ssl_capath in connection_url, or require_tls: false"),
        ("?ssl_ca=", "set ssl_ca or ssl_capath in connection_url, or require_tls: false"),
        (
            "?ssl_ca=/ca.pem&ssl_check_hostname=false",
            "connection_url option 'ssl_check_hostname' disables certificate checks; "
            "remove it, or set require_tls: false",
        ),
        (
            "?ssl_ca=/ca.pem&ssl_verify_cert=true",
            "connection_url option 'ssl_verify_cert' disables certificate checks; "
            "remove it, or set require_tls: false",
        ),
        (
            "?ssl_ca=/ca.pem&ssl_verify_identity=true",
            "connection_url option 'ssl_verify_identity' disables certificate checks; "
            "remove it, or set require_tls: false",
        ),
        (
            "?ssl_ca=/ca.pem&ssl_disabled=true",
            "connection_url option 'ssl_disabled' disables certificate checks; "
            "remove it, or set require_tls: false",
        ),
        ("?ssl_ca=/a.pem&ssl_ca=/b.pem", "connection_url sets 'ssl_ca' more than once"),
    ],
    ids=[
        "none",
        "cert-only",
        "empty-ca",
        "no-hostname",
        "verify-cert",
        "verify-identity",
        "disabled",
        "repeated",
    ],
)
def test_mysql_without_verified_tls_is_rejected(query: str, message: str) -> None:
    assert f"Value error, {_TLS}{message} [type=value_error" in _rejection(_MYSQL + query)


def test_the_tls_error_never_shows_the_url() -> None:
    error = _rejection("mssql+pyodbc://svc:S3cret@db01.corp/master?driver=x")

    assert "S3cret" not in error
    assert "db01" not in error


def test_require_tls_false_allows_an_unverified_pii_server() -> None:
    server = _server(_MSSQL + "&TrustServerCertificate=yes", require_tls=False)

    assert server.require_tls is False


def test_require_tls_is_only_for_all_pii_safe_servers() -> None:
    for value in (True, False):
        with pytest.raises(ValidationError) as info:
            ServerConfig.model_validate(
                {"engine": "sqlserver", "connection_url": _MSSQL, "require_tls": value}
            )
        assert "Value error, metadata servers cannot configure require_tls [type=" in str(
            info.value
        )


def test_metadata_server_needs_no_tls() -> None:
    assert ServerConfig.model_validate({"engine": "sqlserver", "connection_url": _MSSQL})


def test_startup_warns_once_per_pii_server_without_tls(caplog: pytest.LogCaptureFixture) -> None:
    key = base64.b64encode(bytes(range(32))).decode()
    config = AppConfig.model_validate(
        {
            "version": 1,
            "servers": {
                "open": {
                    "engine": "sqlserver",
                    "access_level": "all_pii_safe",
                    "connection_url": _MSSQL,
                    "pii_key_env": "K",
                    "pii_key": key,
                    "pii": _RULES,
                    "require_tls": False,
                },
                "safe": {
                    "engine": "sqlserver",
                    "access_level": "all_pii_safe",
                    "connection_url": _MSSQL + "&Encrypt=yes",
                    "pii_key_env": "K2",
                    "pii_key": base64.b64encode(bytes(range(1, 33))).decode(),
                    "pii": _RULES,
                },
                "meta": {"engine": "sqlserver", "connection_url": _MSSQL},
            },
        }
    )

    with caplog.at_level(logging.WARNING, logger="sql_safe_mcp"):
        create_server(config)

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == ["server=open require_tls=false: PII may travel without verified TLS"]
