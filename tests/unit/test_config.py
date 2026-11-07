from __future__ import annotations

import base64
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from sql_safe_mcp.config import load_config
from sql_safe_mcp.errors import DomainError


def _key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_embedded_environment_values_with_url_encoding(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  legacy:
    engine: sqlserver
    connection_url: mssql+pyodbc://${USER}:${PASSWORD}@${HOST}/master?driver=ODBC+Driver+18+for+SQL+Server
""",
    )

    config = load_config(path, {"USER": "a@b", "PASSWORD": "p:/x", "HOST": "sql01"})

    url = config.servers["legacy"].connection_url.get_secret_value()
    assert "a%40b" in url
    assert "p%3A%2Fx" in url


def test_whole_environment_value_may_contain_complete_url(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  reporting:
    engine: sqlserver
    connection_url: ${REPORTING_SQL_URL}
""",
    )
    expected = "mssql+pyodbc://user:password@sql01/master?driver=ODBC+Driver+18+for+SQL+Server"

    config = load_config(path, {"REPORTING_SQL_URL": expected})

    assert config.servers["reporting"].connection_url.get_secret_value() == expected


def test_pii_key_is_per_server_and_secret_is_redacted(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  legacy:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: LEGACY_KEY
    pii:
      rules:
        - database: "*"
          schema: dbo
          table: Users
          columns: [Email]
""",
    )
    config = load_config(
        path,
        {
            "URL": "mssql+pyodbc://user:password@sql01/master?driver=x&Encrypt=yes",
            "LEGACY_KEY": _key(1),
        },
    )

    server = config.servers["legacy"]
    assert server.key_bytes() == bytes([1]) * 32
    assert "password" not in repr(config)
    assert _key(1) not in repr(config)


def test_access_levels_distinguish_metadata_code_and_all_pii_safe_access(tmp_path: Path) -> None:
    config = load_config(
        _write(
            tmp_path,
            """
version: 1
servers:
  tables:
    engine: sqlserver
    connection_url: ${TABLES_URL}
  routines:
    engine: sqlserver
    access_level: meta_and_code
    connection_url: ${ROUTINES_URL}
  query:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${QUERY_URL}
    pii_key_env: QUERY_KEY
    pii:
      rules: [{database: "*", table: Users, columns: [Email]}]
""",
        ),
        {
            "TABLES_URL": "mssql+pyodbc://u:p@tables/master?driver=x&Encrypt=yes",
            "ROUTINES_URL": "mssql+pyodbc://u:p@routines/master?driver=x&Encrypt=yes",
            "QUERY_URL": "mssql+pyodbc://u:p@query/master?driver=x&Encrypt=yes",
            "QUERY_KEY": _key(1),
        },
    )

    assert {alias: server.access_level for alias, server in config.servers.items()} == {
        "tables": "metadata",
        "routines": "meta_and_code",
        "query": "all_pii_safe",
    }


def test_legacy_pii_safe_access_level_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  legacy:
    engine: sqlserver
    access_level: pii_safe
    connection_url: ${URL}
""",
    )

    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(path, {"URL": "mssql+pyodbc://u:p@legacy/master?driver=x&Encrypt=yes"})


def test_resolves_default_named_and_local_pii_rules_in_stable_order(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
pii_rules:
  - rules:
      - database: "*"
        table: Audit*
        columns: [IpAddress]
  - name: users_pii
    rules:
      - database: "*"
        schema: dbo
        table: Users[0-9]?
        columns: [Email, Phone]
servers:
  default_only:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${DEFAULT_URL}
    pii_key_env: DEFAULT_KEY
  named_and_local:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${NAMED_URL}
    pii_key_env: NAMED_KEY
    pii:
      include: [users_pii]
      rules:
        - database: Billing
          table: Cards
          columns: [HolderName]
        - database: "*"
          table: Audit*
          columns: [IpAddress]
""",
    )
    config = load_config(
        path,
        {
            "DEFAULT_URL": "mssql+pyodbc://u:p@default/master?driver=x&Encrypt=yes",
            "NAMED_URL": "mssql+pyodbc://u:p@named/master?driver=x&Encrypt=yes",
            "DEFAULT_KEY": _key(4),
            "NAMED_KEY": _key(5),
        },
    )

    default_only = config.servers["default_only"].pii
    assert default_only is not None
    assert [rule.table for rule in default_only.rules] == ["Audit*"]
    named_and_local = config.servers["named_and_local"].pii
    assert named_and_local is not None
    assert [rule.table for rule in named_and_local.rules] == [
        "Audit*",
        "Users[0-9]?",
        "Cards",
        "Audit*",
    ]
    assert not hasattr(named_and_local, "include")


@pytest.mark.parametrize(
    ("pii_rules", "pii", "message"),
    [
        (
            """
  - name: shared
    rules: [{database: "*", table: Users, columns: [Email]}]
""",
            "    pii: {include: [missing]}\n",
            "unknown pii rule set 'missing'",
        ),
        (
            """
  - rules: [{database: "*", table: Users, columns: [Email]}]
  - rules: [{database: "*", table: Contacts, columns: [Email]}]
""",
            "",
            "at most one unnamed pii rule set",
        ),
        (
            """
  - name: shared
    rules: [{database: "*", table: Users, columns: [Email]}]
""",
            "    pii: {include: shared}\n",
            "Input should be a valid list",
        ),
    ],
)
def test_rejects_invalid_shared_pii_rule_references(
    tmp_path: Path, pii_rules: str, pii: str, message: str
) -> None:
    path = _write(
        tmp_path,
        """
version: 1
pii_rules:
"""
        + pii_rules
        + """
servers:
  app:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: KEY
"""
        + pii,
    )

    with pytest.raises(DomainError, match=message):
        load_config(
            path,
            {"URL": "mssql+pyodbc://u:p@app/master?driver=x&Encrypt=yes", "KEY": _key(6)},
        )


def test_duplicate_unnamed_rule_sets_have_a_stable_error(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
pii_rules:
  - rules: [{database: "*", table: Users, columns: [Email]}]
  - rules: [{database: "*", table: Contacts, columns: [Email]}]
servers:
  app:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: KEY
""",
    )

    with pytest.raises(DomainError) as raised:
        load_config(
            path, {"URL": "mssql+pyodbc://u:p@app/master?driver=x&Encrypt=yes", "KEY": _key(6)}
        )

    assert raised.value.public_message == (
        "Invalid configuration: at most one unnamed pii rule set is allowed"
    )


def test_named_rule_sets_are_not_implicit_and_local_only_shape_stays_valid(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
pii_rules:
  - name: not_included
    rules: [{database: "*", table: Users, columns: [Email]}]
servers:
  app:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: KEY
    pii:
      rules: [{database: "*", table: Cards, columns: [HolderName]}]
""",
    )

    config = load_config(
        path,
        {"URL": "mssql+pyodbc://u:p@app/master?driver=x&Encrypt=yes", "KEY": _key(7)},
    )

    app_pii = config.servers["app"].pii
    assert app_pii is not None
    assert [rule.table for rule in app_pii.rules] == ["Cards"]


def test_named_rule_sets_are_case_sensitive_and_may_differ_only_by_case(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
pii_rules:
  - name: Users
    rules: [{database: "*", table: Users, columns: [Email]}]
  - name: users
    rules: [{database: "*", table: Contacts, columns: [Email]}]
servers:
  app:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: KEY
    pii: {include: [Users]}
""",
    )

    config = load_config(
        path,
        {"URL": "mssql+pyodbc://u:p@app/master?driver=x&Encrypt=yes", "KEY": _key(7)},
    )

    pii = config.servers["app"].pii
    assert pii is not None
    assert [rule.table for rule in pii.rules] == ["Users"]


@pytest.mark.parametrize("engine", ["mysql", "mariadb"])
def test_shared_rules_check_schema_after_resolution_for_mysql_family(
    tmp_path: Path, engine: str
) -> None:
    template = """
version: 1
pii_rules:
  - name: sqlserver_only
    rules: [{{database: "*", schema: dbo, table: Users, columns: [Email]}}]
servers:
  app:
    engine: {engine}
    access_level: all_pii_safe
    connection_url: mysql+pymysql://u:p@app/database?ssl_ca=/ca.pem
    pii_key_env: KEY
    pii: {pii}
    """
    env = {"KEY": _key(8)}

    unused_path = _write(
        tmp_path,
        template.format(
            engine=engine,
            pii="{rules: [{database: '*', table: Users, columns: [Email]}]}",
        ),
    )
    assert load_config(unused_path, env).servers["app"].engine == engine

    included_path = _write(
        tmp_path,
        template.format(engine=engine, pii="{include: [sqlserver_only]}"),
    )
    with pytest.raises(DomainError, match="cannot set schema"):
        load_config(included_path, env)


@pytest.mark.parametrize(
    ("pii_rules", "pii", "message"),
    [
        (
            """
  - name: duplicate
    rules: [{database: "*", table: Users, columns: [Email]}]
  - name: duplicate
    rules: [{database: "*", table: Contacts, columns: [Email]}]
""",
            "{include: [duplicate]}",
            "duplicate pii rule set name 'duplicate'",
        ),
        (
            """
  - name: shared
    rules: [{database: "*", table: Users, columns: [Email]}]
""",
            "{include: [shared, shared]}",
            "more than once",
        ),
        ("", "{include: []}", "all_pii_safe servers require pii_key_env and pii rules"),
    ],
)
def test_shared_rule_resolution_rejects_ambiguous_or_empty_effective_rules(
    tmp_path: Path, pii_rules: str, pii: str, message: str
) -> None:
    path = _write(
        tmp_path,
        """
version: 1
"""
        + ("pii_rules:\n" + pii_rules if pii_rules else "")
        + """
servers:
  app:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: KEY
    pii: """
        + pii
        + "\n",
    )

    with pytest.raises(DomainError, match=message):
        load_config(
            path, {"URL": "mssql+pyodbc://u:p@app/master?driver=x&Encrypt=yes", "KEY": _key(9)}
        )


def test_default_rules_skip_metadata_and_resolution_continues_to_later_aliases(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
version: 1
pii_rules:
  - rules: [{database: "*", table: Users, columns: [Email]}]
servers:
  metadata:
    engine: sqlserver
    connection_url: ${META_URL}
  app:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${APP_URL}
    pii_key_env: KEY
""",
    )

    config = load_config(
        path,
        {
            "META_URL": "mssql+pyodbc://u:p@meta/master?driver=x&Encrypt=yes",
            "APP_URL": "mssql+pyodbc://u:p@app/master?driver=x&Encrypt=yes",
            "KEY": _key(10),
        },
    )

    assert config.servers["metadata"].pii is None
    app_pii = config.servers["app"].pii
    assert app_pii is not None
    assert [rule.table for rule in app_pii.rules] == ["Users"]


def test_metadata_alias_rejects_shared_rule_configuration_with_a_stable_error(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
version: 1
pii_rules:
  - name: shared
    rules: [{database: "*", table: Users, columns: [Email]}]
servers:
  metadata:
    engine: sqlserver
    connection_url: ${URL}
    pii: {include: [shared]}
""",
    )

    with pytest.raises(DomainError) as raised:
        load_config(path, {"URL": "mssql+pyodbc://u:p@meta/master?driver=x&Encrypt=yes"})

    assert raised.value.public_message == (
        "Invalid configuration: metadata servers cannot configure pii_key_env or pii rules"
    )


def test_meta_and_code_alias_rejects_pii_configuration_with_a_stable_error(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  routines:
    engine: sqlserver
    access_level: meta_and_code
    connection_url: ${URL}
    pii: {rules: [{database: "*", table: Users, columns: [Email]}]}
""",
    )

    with pytest.raises(DomainError) as raised:
        load_config(path, {"URL": "mssql+pyodbc://u:p@routines/master?driver=x&Encrypt=yes"})

    assert raised.value.public_message == (
        "Invalid configuration: meta_and_code servers cannot configure pii_key_env or pii rules"
    )


def test_rejects_reused_key_across_server_aliases(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  one:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL_ONE}
    pii_key_env: KEY_ONE
    pii: {rules: [{database: "*", schema: dbo, table: Users, columns: [Email]}]}
  two:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL_TWO}
    pii_key_env: KEY_TWO
    pii: {rules: [{database: "*", schema: dbo, table: Users, columns: [Email]}]}
""",
    )
    env = {
        "URL_ONE": "mssql+pyodbc://u:p@one/master?driver=x&Encrypt=yes",
        "URL_TWO": "mssql+pyodbc://u:p@two/master?driver=x&Encrypt=yes",
        "KEY_ONE": _key(2),
        "KEY_TWO": _key(2),
    }

    with pytest.raises(DomainError, match="unique per server alias"):
        load_config(path, env)


@pytest.mark.parametrize("length", [0, 16, 31, 33])
def test_rejects_wrong_key_size(tmp_path: Path, length: int) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  legacy:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: KEY
    pii: {rules: [{database: "*", schema: dbo, table: Users, columns: [Email]}]}
""",
    )
    env = {
        "URL": "mssql+pyodbc://u:p@one/master?driver=x&Encrypt=yes",
        "KEY": base64.b64encode(b"x" * length).decode(),
    }

    with pytest.raises(DomainError, match="32 bytes"):
        load_config(path, env)


@pytest.mark.parametrize("engine", ["mysql", "mariadb"])
def test_accepts_mysql_family_metadata_servers(tmp_path: Path, engine: str) -> None:
    path = _write(
        tmp_path,
        f"""
version: 1
servers:
  one:
    engine: {engine}
    connection_url: mysql+pymysql://user:password@localhost/database
""",
    )

    assert load_config(path, {}).servers["one"].engine == engine


@pytest.mark.parametrize(
    ("engine", "url"),
    [
        ("mysql", "mssql+pyodbc://u:p@h/d?driver=x"),
        ("mariadb", "mssql+pyodbc://u:p@h/d?driver=x"),
        ("sqlserver", "mysql+pymysql://u:p@h/d"),
    ],
)
def test_rejects_engine_driver_mismatch(tmp_path: Path, engine: str, url: str) -> None:
    path = _write(
        tmp_path,
        f"""
version: 1
servers:
  one:
    engine: {engine}
    connection_url: {url}
""",
    )

    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(path, {})


@pytest.mark.parametrize("engine", ["mysql", "mariadb"])
@pytest.mark.parametrize(("schema_line", "valid"), [("", True), ("          schema: app\n", False)])
def test_all_pii_safe_for_mysql_family_forbids_rule_schema(
    tmp_path: Path, engine: str, schema_line: str, valid: bool
) -> None:
    path = _write(
        tmp_path,
        f"""
version: 1
servers:
  one:
    engine: {engine}
    access_level: all_pii_safe
    connection_url: mysql+pymysql://user:password@localhost/database?ssl_ca=/ca.pem
    pii_key_env: KEY
    pii:
      rules:
        - database: "*"
{schema_line}          table: users
          columns: [email]
""",
    )
    env = {"KEY": base64.b64encode(b"x" * 32).decode()}

    if valid:
        assert load_config(path, env).servers["one"].access_level == "all_pii_safe"
    else:
        with pytest.raises(DomainError, match="CONFIG_ERROR"):
            load_config(path, env)


@pytest.mark.parametrize(
    ("yaml_text", "environment"),
    [
        (
            """
version: 2
servers:
  legacy:
    engine: sqlserver
    connection_url: ${URL}
""",
            {"URL": "mssql+pyodbc://u:p@host/master?driver=x&Encrypt=yes"},
        ),
        (
            """
version: 1
servers:
  legacy:
    engine: sqlserver
    connection_url: postgresql://u:p@host/database
""",
            {},
        ),
        (
            """
version: 1
servers:
  legacy:
    engine: sqlserver
    connection_url: ${MISSING_URL}
""",
            {},
        ),
    ],
)
def test_rejects_invalid_version_driver_and_missing_environment(
    tmp_path: Path, yaml_text: str, environment: dict[str, str]
) -> None:
    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(_write(tmp_path, yaml_text), environment)


def test_rejects_invalid_base64_key(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
version: 1
servers:
  legacy:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${URL}
    pii_key_env: KEY
    pii: {rules: [{database: "*", schema: dbo, table: Users, columns: [Email]}]}
""",
    )

    with pytest.raises(DomainError, match="valid base64"):
        load_config(
            path, {"URL": "mssql+pyodbc://u:p@host/master?driver=x&Encrypt=yes", "KEY": "!!!"}
        )


@pytest.mark.parametrize(
    "server_fields",
    [
        "access_level: all_pii_safe",
        "access_level: metadata\n    pii_key_env: KEY",
    ],
)
def test_rejects_incomplete_or_forbidden_pii_configuration(
    tmp_path: Path, server_fields: str
) -> None:
    path = _write(
        tmp_path,
        f"""
version: 1
servers:
  legacy:
    engine: sqlserver
    connection_url: ${{URL}}
    {server_fields}
""",
    )

    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(
            path,
            {"URL": "mssql+pyodbc://u:p@host/master?driver=x&Encrypt=yes", "KEY": _key(3)},
        )


def test_validation_error_does_not_echo_secret_extra_field(tmp_path: Path) -> None:
    secret = "do-not-leak-this-token"
    path = _write(
        tmp_path,
        f"""
version: 1
servers:
  legacy:
    engine: sqlserver
    connection_url: mssql+pyodbc://user:password@host/master?driver=x
    accidental_secret: {secret}
""",
    )

    with pytest.raises(DomainError) as raised:
        load_config(path, {})

    message = str(raised.value)
    assert "CONFIG_ERROR" in message
    assert secret not in message
    assert "password" not in message


def test_malformed_yaml_does_not_echo_source_secret(tmp_path: Path) -> None:
    secret = "yaml-secret-value"
    path = _write(tmp_path, f"version: 1\nservers: [\n  {secret}\n")

    with pytest.raises(DomainError) as raised:
        load_config(path, {})

    assert secret not in str(raised.value)


_MINIMAL_SERVER = """
servers:
  reporting:
    engine: sqlserver
    connection_url: mssql+pyodbc://u:p@h/master?driver=x
"""


def test_logging_level_defaults_to_info(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, "version: 1\n" + _MINIMAL_SERVER), {})

    assert config.logging.level == "INFO"


@pytest.mark.parametrize("level", ["DEBUG", "INFO", "WARNING", "ERROR"])
def test_logging_level_accepts_standard_levels(tmp_path: Path, level: str) -> None:
    path = _write(tmp_path, f"version: 1\nlogging:\n  level: {level}\n" + _MINIMAL_SERVER)

    assert load_config(path, {}).logging.level == level


def test_logging_audit_is_off_by_default_and_opt_in(tmp_path: Path) -> None:
    default = load_config(_write(tmp_path, "version: 1\n" + _MINIMAL_SERVER), {})
    enabled = load_config(
        _write(tmp_path, "version: 1\nlogging:\n  audit: true\n" + _MINIMAL_SERVER), {}
    )

    assert default.logging.audit is False
    assert enabled.logging.audit is True


@pytest.mark.parametrize("body", ["  level: debug\n", "  level: TRACE\n", "  file: x.log\n"])
def test_logging_rejects_unknown_levels_and_keys(tmp_path: Path, body: str) -> None:
    path = _write(tmp_path, "version: 1\nlogging:\n" + body + _MINIMAL_SERVER)

    with pytest.raises(DomainError) as error:
        load_config(path, {})

    assert "logging" in str(error.value)


_HOST_PLACEHOLDER_CONFIG = """
version: 1
servers:
  dev:
    engine: sqlserver
    connection_url: mssql+pyodbc://${USER}:${PASSWORD}@${SERVER}/master?driver=ODBC+Driver+18+for+SQL+Server
"""


def test_host_and_port_in_one_embedded_placeholder_is_rejected_with_a_hint(
    tmp_path: Path,
) -> None:
    env = {"USER": "sa", "PASSWORD": "s3cr3t#", "SERVER": "10.12.11.107:1433"}

    with pytest.raises(DomainError) as raised:
        load_config(_write(tmp_path, _HOST_PLACEHOLDER_CONFIG), env)

    message = str(raised.value)
    assert "servers.dev" in message
    assert "host" in message
    assert "separate" in message
    for leaked in ("10.12.11.107", "1433", "s3cr3t", "%3A"):
        assert leaked not in message


def test_host_and_port_in_separate_placeholders_load(tmp_path: Path) -> None:
    text = _HOST_PLACEHOLDER_CONFIG.replace("${SERVER}", "${HOST}:${PORT}")
    env = {"USER": "sa", "PASSWORD": "s3cr3t#", "HOST": "10.12.11.107", "PORT": "1433"}

    config = load_config(_write(tmp_path, text), env)

    url = make_url(config.servers["dev"].connection_url.get_secret_value())
    assert (url.host, url.port, url.password) == ("10.12.11.107", 1433, "s3cr3t#")


def test_a_whole_url_placeholder_may_carry_host_and_port(tmp_path: Path) -> None:
    text = """
version: 1
servers:
  dev:
    engine: sqlserver
    connection_url: ${DEV_URL}
"""
    env = {"DEV_URL": "mssql+pyodbc://sa:p@10.12.11.107:1433/master?driver=x&Encrypt=yes"}

    config = load_config(_write(tmp_path, text), env)

    assert make_url(config.servers["dev"].connection_url.get_secret_value()).port == 1433


_DENY_ENV = {"URL": "mssql+pyodbc://u:p@peds/master?driver=x&Encrypt=yes", "KEY": _key(7)}


def _peds_config(pii: str, shared: str = "") -> str:
    return f"""
version: 1
{shared}
servers:
  peds:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: ${{URL}}
    pii_key_env: KEY
    pii:
{pii}
"""


def test_pii_mode_defaults_to_protect(tmp_path: Path) -> None:
    text = _peds_config('      rules: [{database: "*", table: Users, columns: [Email]}]')

    pii = load_config(_write(tmp_path, text), _DENY_ENV).servers["peds"].pii

    assert pii is not None
    assert (pii.mode, pii.exposed_columns, pii.deny) == ("protect", [], [])


def test_deny_by_default_alias_loads_without_database_on_exposed_and_deny(tmp_path: Path) -> None:
    text = _peds_config(
        """      mode: deny-by-default
      exposed_columns:
        - {table: Visits, columns: [VisitId, DepartmentCode]}
      deny:
        - {table: "*", columns: [Notes, Anamnesis]}
        - {table: Attachments, columns: ["*"]}"""
    )

    pii = load_config(_write(tmp_path, text), _DENY_ENV).servers["peds"].pii

    assert pii is not None
    assert pii.mode == "deny-by-default"
    assert pii.rules == []
    assert [rule.database for rule in pii.exposed_columns + pii.deny] == ["*", "*", "*"]
    assert pii.deny[1].columns == ["*"]


@pytest.mark.parametrize(
    "pii",
    [
        '      rules: [{table: Users, columns: ["*"]}]',
        '      mode: deny-by-default\n      exposed_columns: [{table: Users, columns: ["*"]}]',
        "      mode: allow-all",
        "      exposed_columns: []",
    ],
)
def test_invalid_deny_shapes_are_config_errors(tmp_path: Path, pii: str) -> None:
    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(_write(tmp_path, _peds_config(pii)), _DENY_ENV)


@pytest.mark.parametrize("section", ["exposed_columns", "deny"])
def test_mysql_exposed_and_deny_rules_cannot_set_schema(tmp_path: Path, section: str) -> None:
    text = f"""
version: 1
servers:
  m:
    engine: mysql
    access_level: all_pii_safe
    connection_url: ${{URL}}
    pii_key_env: KEY
    pii:
      mode: deny-by-default
      {section}: [{{schema: dbo, table: people, columns: [email]}}]
"""
    env = {**_DENY_ENV, "URL": "mysql+pymysql://u:p@h/db?ssl_ca=/ca.pem"}
    with pytest.raises(DomainError, match="cannot set schema"):
        load_config(_write(tmp_path, text), env)


def test_deny_by_default_is_only_for_all_pii_safe_servers(tmp_path: Path) -> None:
    text = """
version: 1
servers:
  meta:
    engine: sqlserver
    connection_url: ${URL}
    pii:
      mode: deny-by-default
"""
    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(_write(tmp_path, text), _DENY_ENV)


def test_shared_rule_sets_carry_the_token_domain(tmp_path: Path) -> None:
    shared = """pii_rules:
  - name: people
    rules:
      - {database: "*", table: Patients, columns: [Email], domain: contact}
      - {database: "*", table: Patients, columns: [Dob]}"""
    text = _peds_config("      include: [people]", shared)

    pii = load_config(_write(tmp_path, text), _DENY_ENV).servers["peds"].pii

    assert pii is not None
    assert [rule.domain for rule in pii.rules] == ["contact", None]


@pytest.mark.parametrize("domain", ["", "-x", "has space", "a/b", "é"])
def test_token_domain_must_look_like_an_alias(tmp_path: Path, domain: str) -> None:
    rule = f'{{database: "*", table: Patients, columns: [Email], domain: "{domain}"}}'
    pii = f"      rules: [{rule}]"
    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(_write(tmp_path, _peds_config(pii, "")), _DENY_ENV)


@pytest.mark.parametrize("section", ["exposed_columns", "deny"])
def test_token_domain_is_only_for_protection_rules(tmp_path: Path, section: str) -> None:
    pii = (
        "      mode: deny-by-default\n"
        f'      {section}: [{{table: Patients, columns: [Email], domain: "contact"}}]'
    )
    with pytest.raises(DomainError, match="CONFIG_ERROR"):
        load_config(_write(tmp_path, _peds_config(pii, "")), _DENY_ENV)


def test_shared_rule_sets_carry_deny_and_exposed_columns(tmp_path: Path) -> None:
    shared = """pii_rules:
  - deny: [{table: "*", columns: [Notes]}]
  - name: visits
    exposed_columns: [{table: Visits, columns: [VisitId]}]
    deny: [{table: Attachments, columns: ["*"]}]"""
    text = _peds_config(
        """      mode: deny-by-default
      include: [visits]
      deny: [{table: Secrets, columns: ["*"]}]""",
        shared,
    )

    pii = load_config(_write(tmp_path, text), _DENY_ENV).servers["peds"].pii

    assert pii is not None
    assert pii.mode == "deny-by-default"
    assert [rule.table for rule in pii.deny] == ["*", "Attachments", "Secrets"]
    assert [rule.table for rule in pii.exposed_columns] == ["Visits"]


def _ttl_config(runtime: str = "") -> str:
    return (
        f"version: 1\n{runtime}servers:\n"
        "  one:\n"
        "    engine: sqlserver\n"
        "    access_level: all_pii_safe\n"
        "    connection_url: mssql+pyodbc://u:p@one/master?driver=x&Encrypt=yes\n"
        "    pii_key_env: KEY_ONE\n"
        '    pii: {rules: [{database: "*", schema: dbo, table: Users, columns: [Email]}]}\n'
    )


def test_token_ttl_is_off_by_default_and_bounded(tmp_path: Path) -> None:
    env = {"KEY_ONE": _key(1)}
    default = load_config(_write(tmp_path, _ttl_config()), env)
    set_ttl = load_config(
        _write(tmp_path, _ttl_config("runtime: {token_ttl_seconds: 86400}\n")), env
    )

    assert default.runtime.token_ttl_seconds is None
    assert set_ttl.runtime.token_ttl_seconds == 86400
    for bad in (0, -1, 315_360_001, "true"):
        text = _ttl_config(f"runtime: {{token_ttl_seconds: {bad}}}\n")
        with pytest.raises(DomainError) as raised:
            load_config(_write(tmp_path, text), env)
        assert "token_ttl_seconds" in raised.value.public_message
