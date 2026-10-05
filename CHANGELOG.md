# Changelog

All notable externally observable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and uses the
categories `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, and `Security`.

## [Unreleased]

## [1.5.2] - 2026-10-05

### Security

- `execute_sql` now rejects a projection whose alias names anything other than a direct column,
  a literal, or `COUNT(*)`, such as `SELECT (Email) AS e FROM Users`. Before, the expression was
  classified as a literal, so a protected column wrapped in parentheses was returned in clear,
  and on MySQL/MariaDB a projected comparison such as `(Email > 'm') AS x` acted as an oracle on
  the protected value. The lineage stage also fails closed on any untraceable projection.

## [1.5.1] - 2026-09-23

### Fixed

- Malformed `connection_url` values now return a sanitized `CONFIG_ERROR` instead of an unhandled
  traceback. DBAPI errors now prefer supported SQLSTATE and native error codes over driver text.

### Security

- The Bash and PowerShell demo seeding scripts reject reader-password characters unsafe for their
  SQL command boundary.

## [1.5.0] - 2026-09-22

### Changed

- `access_level` now defaults to table-only `metadata`; `meta_and_code` restores stored-procedure
  discovery and definitions, and `all_pii_safe` enables PII-protected `execute_sql`. The former
  `pii_safe` value is rejected and must be replaced with `all_pii_safe`.

## [1.4.0] - 2026-09-22

### Added

- `sql-safe-mcp --gen-pii-key [N]` generates one base64-encoded 32-byte PII key by default, or
  `N` keys as one value per line, without loading configuration or connecting to a database.
- PII table rules now accept case-insensitive full shell-glob patterns, and `pii_rules` can define
  shared unnamed defaults or named sets explicitly included by `pii_safe` aliases. Shared rules are
  flattened at startup in deterministic default, include, and local order.

## [1.3.1] - 2026-09-21

### Changed

- A `${NAME}` placeholder embedded in `connection_url` whose value puts an encoded character into
  the host, such as a `host:port` value whose `:` becomes `%3A`, is now a startup error that names
  the cause. Before, the server started and every call failed after the driver's login timeout.

## [1.3.0] - 2026-09-21

### Added

- Diagnostic logging to stderr, controlled by the new `logging.level` setting (`DEBUG`, `INFO`,
  `WARNING`, or `ERROR`; default `INFO`). It records each database connection attempt (server alias,
  database, elapsed time, and on failure the driver error class, SQLSTATE or code, and message with
  the connection URL's user name and password masked and its host shown as the server alias) and each tool operation's outcome.
  Connection URLs, credentials, keys, tokens, SQL, bind values, and rows are never logged.

### Changed

- `TIMEOUT` and `CONNECTION_FAILED` errors now carry a `Reference` that matches the `reference=`
  field of the log line for the same failure.

## [1.2.0] - 2026-09-20

### Added

- MySQL and MariaDB support: `engine: mysql` or `engine: mariadb` with a `mysql+pymysql://` URL.
  All seven tools work on them. MySQL and MariaDB have no schema level, so `schema` is always
  `null` in responses and a `db.table` name is rejected as a cross-database reference.
- `execute_sql` and `pii_safe` on MySQL and MariaDB, with `LIMIT` in place of `TOP`. A `pii` rule
  for these engines must not set `schema`. `TIME` results are returned as `time` values within a
  day; longer values fail with `DATABASE_ERROR`.
- Stored procedures on MySQL and MariaDB report the body from `information_schema.ROUTINES`, which
  is `null` when the login may not see it.
- `COUNT(*)` is accepted on the `mysql` dialect.

### Changed

- **Breaking:** the project is renamed from `sql-mini-mcp` to `sql-safe-mcp`. The package, the
  Python module (`sql_safe_mcp`), the command (`sql-safe-mcp`), the example configuration file, and
  every environment variable (`SQL_MINI_MCP_CONFIG` is now `SQL_SAFE_MCP_CONFIG`) change; the old
  names are not kept as aliases. The `sql-mini-mcp` package on PyPI becomes a deprecated shim that
  depends on `sql-safe-mcp`.
- The `QUERY_REJECTED` reason for a non-integer row limit now reads
  `TOP/LIMIT must be a non-negative integer literal`.

### Security

- MySQL and MariaDB sessions drop `NO_BACKSLASH_ESCAPES`, so the string escaping in the generated
  SQL always means what the validated query means, even if the server enables that mode.
- The validation pipeline takes its SQL dialect only from the trusted server configuration and
  requires it explicitly; policy, tokens, and the validated query are shared by every engine.

## [1.1.0] - 2026-09-20

### Changed

- `QUERY_REJECTED` errors from `execute_sql` now come from a fixed catalog of reasons. The wording
  for unsupported syntax names the construct as `unsupported construct: <Node>` or
  `unsupported option: <Node>.<argument>`; other reasons keep their earlier text.

### Security

- `execute_sql` no longer forwards comments from the caller's SQL to the database. The executed
  statement is generated only from the validated query, so comment text can never become
  executable text.

## [1.0.0] - 2026-09-20

### Added

- `execute_sql` tool for `pii_safe` SQL Server aliases. It runs one restricted `SELECT`, returns
  configured PII columns as alias-bound tokens, accepts those tokens only in `=` and `IN`
  predicates, and returns at most `max_rows` rows with a `truncated` flag. Servers with
  `access_level: metadata` return `ACCESS_LEVEL_DENIED`.

## [0.9.1] - 2026-09-20

### Added

- Publishing of release-tag packages to PyPI and their metadata to the MCP Registry.

### Fixed

- Source distributions now include only release files, excluding local development caches.

## [0.9.0] - 2026-09-20

### Added

- Read-only SQL Server metadata tools for configured server aliases, databases, tables, and
  stored procedures.
