from __future__ import annotations

import base64
import binascii
import os
import re
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Literal
from urllib.parse import quote

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from sql_safe_mcp.errors import DomainError, ErrorCode

_ENV_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
_FULL_ENV_PATTERN = re.compile(r"^\$\{([A-Z_][A-Z0-9_]*)\}$")
_SERVER_ALIAS_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]*"


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_concurrent_db_operations: int = Field(default=8, ge=1, le=128)
    engine_cache_size: int = Field(default=32, ge=1, le=1024)
    pool_size: int = Field(default=2, ge=1, le=32)
    max_overflow: int = Field(default=2, ge=0, le=64)
    pool_timeout_seconds: int = Field(default=10, ge=1, le=300)
    statement_timeout_seconds: int = Field(default=30, ge=1, le=3600)
    max_definition_chars: int = Field(default=262_144, ge=1024, le=10_000_000)
    default_max_rows: int = Field(default=200, ge=1, le=100_000)
    hard_max_rows: int = Field(default=1000, ge=1, le=100_000)
    max_sql_chars: int = Field(default=65_536, ge=256, le=1_000_000)
    max_ast_nodes: int = Field(default=2000, ge=10, le=100_000)
    max_joins: int = Field(default=8, ge=0, le=100)
    max_in_list_items: int = Field(default=500, ge=1, le=100_000)

    @model_validator(mode="after")
    def validate_row_limits(self) -> RuntimeConfig:
        if self.default_max_rows > self.hard_max_rows:
            raise ValueError("default_max_rows cannot exceed hard_max_rows")
        return self


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    audit: bool = False


class PiiRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    database: str = Field(min_length=1)
    schema_: str | None = Field(default=None, alias="schema")
    table: str = Field(min_length=1)
    columns: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_wildcards(self) -> PiiRule:
        if self.schema_ and "*" in self.schema_:
            raise ValueError("wildcards are allowed only in pii rule table or database")
        if self.database != "*" and "*" in self.database:
            raise ValueError("database must be an exact name or '*'")
        folded = [column.casefold() for column in self.columns]
        if len(folded) != len(set(folded)):
            raise ValueError("pii rule columns must be unique")
        return self


class PiiScopeRule(PiiRule):
    """An `exposed_columns` or `deny` entry; the database defaults to any."""

    database: str = Field(default="*", min_length=1)


def _check_column_wildcards(
    rules: list[PiiRule], exposed: list[PiiScopeRule], deny: list[PiiScopeRule]
) -> None:
    if any("*" in column for rule in [*rules, *exposed] for column in rule.columns):
        raise ValueError("pii rules and exposed_columns cannot list '*' columns; only deny can")
    if any("*" in column and rule.columns != ["*"] for rule in deny for column in rule.columns):
        raise ValueError("a deny column wildcard must be exactly ['*']")


class PiiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["protect", "deny-by-default"] = "protect"
    rules: list[PiiRule] = Field(default_factory=list)
    exposed_columns: list[PiiScopeRule] = Field(default_factory=list)
    deny: list[PiiScopeRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_shape(self) -> PiiConfig:
        _check_column_wildcards(self.rules, self.exposed_columns, self.deny)
        if self.mode == "protect" and not (self.rules or self.deny):
            raise ValueError("pii requires at least one rule or deny entry")
        return self


class PiiConfigInput(BaseModel):
    """The YAML-only PII shape before shared rules are resolved."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["protect", "deny-by-default"] = "protect"
    include: list[str] = Field(default_factory=list)
    rules: list[PiiRule] = Field(default_factory=list)
    exposed_columns: list[PiiScopeRule] = Field(default_factory=list)
    deny: list[PiiScopeRule] = Field(default_factory=list)


class PiiRuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, pattern=rf"^{_SERVER_ALIAS_PATTERN}$")
    rules: list[PiiRule] = Field(default_factory=list)
    exposed_columns: list[PiiScopeRule] = Field(default_factory=list)
    deny: list[PiiScopeRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_not_empty(self) -> PiiRuleSet:
        if not (self.rules or self.exposed_columns or self.deny):
            raise ValueError("a pii rule set needs rules, exposed_columns or deny")
        return self


_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")

_DRIVERNAMES = {
    "sqlserver": "mssql+pyodbc",
    "mysql": "mysql+pymysql",
    "mariadb": "mysql+pymysql",
}


class ServerConfigBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engine: Literal["sqlserver", "mysql", "mariadb"]
    access_level: Literal["metadata", "meta_and_code", "all_pii_safe"] = "metadata"
    connection_url: SecretStr
    pii_key_env: str | None = Field(default=None, pattern=r"^[A-Z_][A-Z0-9_]*$")
    pii_key: SecretStr | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def validate_connection_url(self) -> ServerConfigBase:
        try:
            url = make_url(self.connection_url.get_secret_value())
        except ArgumentError as exc:
            raise ValueError("connection_url must be a valid SQLAlchemy URL") from exc
        if url.host and _PERCENT_ESCAPE.search(url.host):
            raise ValueError(
                "connection_url host contains an encoded character; a ${NAME} placeholder inside "
                "a URL is URL-encoded, so a 'host:port' value breaks. "
                "Use separate ${HOST} and ${PORT} variables"
            )
        driver = url.drivername
        expected = _DRIVERNAMES[self.engine]
        if driver != expected:
            raise ValueError(f"engine {self.engine!r} requires SQLAlchemy dialect {expected!r}")
        return self

    def key_bytes(self) -> bytes | None:
        if self.pii_key is None:
            return None
        return base64.b64decode(self.pii_key.get_secret_value(), validate=True)


class ServerConfig(ServerConfigBase):
    pii: PiiConfig | None = None

    @model_validator(mode="after")
    def validate_security_shape(self) -> ServerConfig:
        if self.access_level == "all_pii_safe":
            if not self.pii_key_env or self.pii is None:
                raise ValueError("all_pii_safe servers require pii_key_env and pii rules")
            scoped = [*self.pii.rules, *self.pii.exposed_columns, *self.pii.deny]
            if self.engine != "sqlserver" and any(rule.schema_ for rule in scoped):
                raise ValueError(f"pii rules for engine {self.engine!r} cannot set schema")
        elif self.pii_key_env is not None or self.pii is not None:
            raise ValueError(
                f"{self.access_level} servers cannot configure pii_key_env or pii rules"
            )
        return self


class ServerConfigInput(ServerConfigBase):
    pii: PiiConfigInput | None = None


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    servers: dict[str, ServerConfig] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_aliases_and_keys(self) -> AppConfig:
        seen_keys: dict[bytes, str] = {}
        for alias, server in self.servers.items():
            if not re.fullmatch(_SERVER_ALIAS_PATTERN, alias):
                raise ValueError(f"invalid server alias {alias!r}")
            key = server.key_bytes()
            if key is None:
                continue
            if len(key) != 32:
                raise ValueError(f"PII key for server {alias!r} must decode to 32 bytes")
            if previous := seen_keys.get(key):
                raise ValueError(
                    f"PII keys must be unique per server alias; {alias!r} duplicates {previous!r}"
                )
            seen_keys[key] = alias
        return self


class AppConfigInput(BaseModel):
    """Strict top-level YAML shape, including shared PII rule declarations."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    pii_rules: list[PiiRuleSet] | None = Field(default=None, min_length=1)
    servers: dict[str, ServerConfigInput] = Field(min_length=1)


def _expand_connection_url(template: str, environ: Mapping[str, str]) -> str:
    full_match = _FULL_ENV_PATTERN.fullmatch(template)
    if full_match:
        name = full_match.group(1)
        if name not in environ:
            raise ValueError(f"missing environment variable {name}")
        return environ[name]

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in environ:
            raise ValueError(f"missing environment variable {name}")
        return quote(environ[name], safe="")

    expanded = _ENV_PATTERN.sub(replace, template)
    if "${" in expanded:
        raise ValueError("invalid environment placeholder in connection_url")
    return expanded


def _validation_summary(error: ValidationError) -> str:
    issues: list[str] = []
    for issue in error.errors(include_url=False, include_context=False, include_input=False):
        location = ".".join(str(part) for part in issue["loc"])
        issues.append(f"{location}: {issue['msg']}" if location else str(issue["msg"]))
    return "; ".join(issues)


def _resolve_pii_rules(raw: dict[object, object], config: AppConfigInput) -> dict[object, object]:
    """Flatten shared PII rules before runtime configuration is constructed."""

    default_set: PiiRuleSet | None = None
    named_sets: dict[str, PiiRuleSet] = {}
    for rule_set in config.pii_rules or []:
        if rule_set.name is None:
            if default_set is not None:
                raise ValueError("at most one unnamed pii rule set is allowed")
            default_set = rule_set
            continue
        if rule_set.name in named_sets:
            raise ValueError(f"duplicate pii rule set name {rule_set.name!r}")
        named_sets[rule_set.name] = rule_set

    resolved = deepcopy(raw)
    resolved.pop("pii_rules", None)
    servers = resolved["servers"]
    assert isinstance(servers, dict)
    for alias, server in config.servers.items():
        server_data = servers[alias]
        assert isinstance(server_data, dict)
        if server.access_level != "all_pii_safe":
            if server.pii is not None:
                raise ValueError(
                    f"{server.access_level} servers cannot configure pii_key_env or pii rules"
                )
            continue

        sets: list[PiiRuleSet | PiiConfigInput] = [default_set] if default_set is not None else []
        mode = "protect"
        local = server.pii
        if local is not None:
            mode = local.mode
            included: set[str] = set()
            for name in local.include:
                if name not in named_sets:
                    raise ValueError(f"server {alias!r} includes unknown pii rule set {name!r}")
                if name in included:
                    raise ValueError(
                        f"server {alias!r} includes pii rule set {name!r} more than once"
                    )
                included.add(name)
                sets.append(named_sets[name])
            sets.append(local)
        merged = {
            field: [
                rule.model_dump(by_alias=True) for item in sets for rule in getattr(item, field)
            ]
            for field in ("rules", "exposed_columns", "deny")
        }
        server_data["pii"] = (
            {"mode": mode, **merged} if any(merged.values()) or mode != "protect" else None
        )
    return resolved


def load_config(path: str | Path, environ: Mapping[str, str] | None = None) -> AppConfig:
    env = os.environ if environ is None else environ
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("configuration root must be a mapping")
        servers = raw.get("servers")
        if not isinstance(servers, dict):
            raise ValueError("servers must be a mapping")
        for alias, value in servers.items():
            if not isinstance(value, dict):
                raise ValueError(f"server {alias!r} must be a mapping")
            url = value.get("connection_url")
            if not isinstance(url, str):
                raise ValueError(f"server {alias!r} requires connection_url")
            value["connection_url"] = _expand_connection_url(url, env)
            key_env = value.get("pii_key_env")
            if key_env is not None:
                if not isinstance(key_env, str) or key_env not in env:
                    raise ValueError(f"missing PII key environment variable {key_env!r}")
                try:
                    decoded = base64.b64decode(env[key_env], validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise ValueError(f"PII key for server {alias!r} is not valid base64") from exc
                if len(decoded) != 32:
                    raise ValueError(f"PII key for server {alias!r} must decode to 32 bytes")
                value["pii_key"] = env[key_env]
        input_config = AppConfigInput.model_validate(raw)
        return AppConfig.model_validate(_resolve_pii_rules(raw, input_config))
    except ValidationError as exc:
        raise DomainError(
            ErrorCode.CONFIG_ERROR,
            f"Invalid configuration: {_validation_summary(exc)}",
        ) from exc
    except (OSError, yaml.YAMLError) as exc:
        raise DomainError(ErrorCode.CONFIG_ERROR, "Invalid configuration file.") from exc
    except ValueError as exc:
        raise DomainError(ErrorCode.CONFIG_ERROR, f"Invalid configuration: {exc}") from exc
