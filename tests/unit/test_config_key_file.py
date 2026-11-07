from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

from sql_safe_mcp.config import load_config
from sql_safe_mcp.errors import DomainError

_URL = "mssql+pyodbc://u:p@app/master?driver=x&Encrypt=yes"
_POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file permissions")


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


def _config(tmp_path: Path, key_source: str, *, level: str = "all_pii_safe") -> Path:
    pii = "    pii:\n      rules:\n        - {database: '*', table: Users, columns: [Email]}\n"
    path = tmp_path / "config.yaml"
    path.write_text(
        "version: 1\n"
        "servers:\n"
        "  app:\n"
        "    engine: sqlserver\n"
        f"    access_level: {level}\n"
        "    connection_url: ${URL}\n"
        f"{key_source}"
        f"{pii if level == 'all_pii_safe' else ''}",
        encoding="utf-8",
    )
    return path


def _key_file(path: Path, content: str | bytes, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    path.chmod(mode)
    return path


def _error(path: Path, environ: dict[str, str] | None = None) -> str:
    with pytest.raises(DomainError) as raised:
        load_config(path, {"URL": _URL, **(environ or {})})
    return str(raised.value)


def test_key_is_read_from_an_absolute_file_path(tmp_path: Path) -> None:
    key_file = _key_file(tmp_path / "keys" / "app.key", _key(3))
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n")

    server = load_config(path, {"URL": _URL}).servers["app"]

    assert server.key_bytes() == bytes([3]) * 32
    assert _key(3) not in repr(server)


def test_relative_key_file_resolves_against_the_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    _key_file(config_dir / "secrets" / "app.key", _key(4))
    path = _config(config_dir, "    pii_key_file: secrets/app.key\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _key_file(elsewhere / "secrets" / "app.key", _key(5))
    monkeypatch.chdir(elsewhere)

    server = load_config(path, {"URL": _URL}).servers["app"]

    assert server.key_bytes() == bytes([4]) * 32


@pytest.mark.parametrize("ending", ["\n", "\r\n", "  \n\n"])
def test_trailing_whitespace_in_the_key_file_is_ignored(tmp_path: Path, ending: str) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(6) + ending)
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n")

    assert load_config(path, {"URL": _URL}).servers["app"].key_bytes() == bytes([6]) * 32


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("!!!", "PII key for server 'app' is not valid base64"),
        (base64.b64encode(b"k" * 16).decode(), "PII key for server 'app' must decode to 32 bytes"),
        (b"\xff\xfe", "PII key for server 'app' is not valid base64"),
        ("A" * 1025, "PII key file for server 'app' is larger than 1024 bytes"),
    ],
)
def test_bad_key_file_content_is_rejected_without_echoing_it(
    tmp_path: Path, content: str | bytes, message: str
) -> None:
    key_file = _key_file(tmp_path / "app.key", content)
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n")

    error = _error(path)

    assert error == f"[CONFIG_ERROR] Invalid configuration: {message}"


def test_missing_key_file_is_a_config_error_without_its_path(tmp_path: Path) -> None:
    path = _config(tmp_path, "    pii_key_file: secret-dir-marker/app.key\n")

    error = _error(path)

    assert (
        error
        == "[CONFIG_ERROR] Invalid configuration: PII key file for server 'app' cannot be read"
    )


@_POSIX_ONLY  # Windows refuses to open a directory: "cannot be read"
def test_key_file_must_be_a_regular_file(tmp_path: Path) -> None:
    (tmp_path / "keys").mkdir()
    path = _config(tmp_path, "    pii_key_file: keys\n")

    assert _error(path).endswith("PII key file for server 'app' is not a regular file")


def test_key_env_and_key_file_are_mutually_exclusive(tmp_path: Path) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(7))
    path = _config(tmp_path, f"    pii_key_env: APP_KEY\n    pii_key_file: '{key_file}'\n")

    error = _error(path, {"APP_KEY": _key(8)})

    assert "servers.app: Value error, set either pii_key_env or pii_key_file, not both" in error


def test_metadata_server_cannot_configure_a_key_file(tmp_path: Path) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(7))
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n", level="metadata")

    error = _error(path)

    assert "metadata servers cannot configure pii_key_env, pii_key_file or pii rules" in error


def test_file_key_equal_to_another_alias_env_key_is_rejected(tmp_path: Path) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(9))
    path = tmp_path / "config.yaml"
    rules = "    pii:\n      rules:\n        - {database: '*', table: Users, columns: [Email]}\n"
    path.write_text(
        "version: 1\nservers:\n"
        f"  one:\n    engine: sqlserver\n    access_level: all_pii_safe\n"
        f"    connection_url: ${{URL}}\n    pii_key_file: '{key_file}'\n{rules}"
        f"  two:\n    engine: sqlserver\n    access_level: all_pii_safe\n"
        f"    connection_url: ${{URL}}\n    pii_key_env: TWO_KEY\n{rules}",
        encoding="utf-8",
    )

    assert "PII keys must be unique per server alias; 'two' duplicates 'one'" in _error(
        path, {"TWO_KEY": _key(9)}
    )


@_POSIX_ONLY
@pytest.mark.parametrize("mode", [0o600, 0o400, 0o640, 0o440])
def test_key_file_modes_without_other_access_are_accepted(tmp_path: Path, mode: int) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(10), mode)
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n")

    assert load_config(path, {"URL": _URL}).servers["app"].key_bytes() == bytes([10]) * 32


@_POSIX_ONLY
@pytest.mark.parametrize("mode", [0o644, 0o604, 0o620, 0o660, 0o601, 0o610])
def test_key_file_readable_by_others_or_writable_by_group_is_rejected(
    tmp_path: Path, mode: int
) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(11), mode)
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n")

    assert _error(path).endswith(
        "PII key file for server 'app' must not be writable by group or accessible by others "
        "(use mode 0600, 0640 or 0440)"
    )


@_POSIX_ONLY
def test_key_file_owned_by_another_user_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(12))
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n")
    owner = os.stat(key_file).st_uid
    monkeypatch.setattr(os, "geteuid", lambda: owner + 1)

    error = _error(path)

    assert error.endswith("PII key file for server 'app' must be owned by the server user or root")


@_POSIX_ONLY
def test_key_file_owned_by_root_is_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_file = _key_file(tmp_path / "app.key", _key(13), 0o440)
    path = _config(tmp_path, f"    pii_key_file: '{key_file}'\n")
    real_fstat = os.fstat

    def root_owned(fd: int) -> os.stat_result:
        info = list(real_fstat(fd))
        info[4] = 0  # st_uid
        return os.stat_result(info)

    monkeypatch.setattr(os, "fstat", root_owned)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    assert load_config(path, {"URL": _URL}).servers["app"].key_bytes() == bytes([13]) * 32


def test_key_env_variable_is_removed_from_the_process_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _config(tmp_path, "    pii_key_env: SCRUB_ME_KEY\n")
    monkeypatch.setenv("URL", _URL)
    monkeypatch.setenv("SCRUB_ME_KEY", _key(14))

    server = load_config(path).servers["app"]

    assert server.key_bytes() == bytes([14]) * 32
    assert "SCRUB_ME_KEY" not in os.environ
    assert os.environ["URL"] == _URL


def test_explicit_environ_mapping_is_left_untouched(tmp_path: Path) -> None:
    path = _config(tmp_path, "    pii_key_env: APP_KEY\n")
    environ = {"URL": _URL, "APP_KEY": _key(15)}

    load_config(path, environ)

    assert environ == {"URL": _URL, "APP_KEY": _key(15)}


def test_key_env_variable_stays_when_loading_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _config(tmp_path, "    pii_key_env: KEEP_ME_KEY\n    unknown: 1\n")
    monkeypatch.setenv("URL", _URL)
    monkeypatch.setenv("KEEP_ME_KEY", _key(16))

    with pytest.raises(DomainError):
        load_config(path)

    assert os.environ["KEEP_ME_KEY"] == _key(16)
