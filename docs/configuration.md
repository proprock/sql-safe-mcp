# Configuration

Connection topology lives in a YAML file. Secrets live in the process environment and are pulled in
with `${NAME}` placeholders. Three complete, commented templates are available. Copy one to
`sql-safe-mcp.yaml` and replace only its environment-variable names; never put a URL, credential,
or PII key into the file.

| Template | Use it when | It demonstrates |
|---|---|---|
| [simple](../sql-safe-mcp.example-simple.yaml) | You need one SQL Server instance and schema metadata only. | One `metadata` alias, with no PII or logging settings. |
| [multi](../sql-safe-mcp.example-multi.yaml) | You need several independent instances and local PII policies. | SQL Server and MySQL aliases; every PII rule is built into its alias. |
| [shared](../sql-safe-mcp.example-shared.yaml) | Several PII-safe aliases need reusable policies or you need explicit operating limits. | Shared default/named PII sets, local additions, all runtime limits, and logging. |

## Complete examples

All three templates comment each selected setting and identify the allowed choice when the setting
uses a fixed set of values. They are valid independent starting points, not fragments to combine.

### Simple: one metadata-only server

[`sql-safe-mcp.example-simple.yaml`](../sql-safe-mcp.example-simple.yaml) is the README quick-start
configuration. It intentionally has no `logging`, `runtime`, `pii_key_env`, or `pii` blocks, so
the defaults apply and `execute_sql` is unavailable. It is SQL Server metadata only; no PII rule
means there is no SQL Server `schema` choice to configure.

### Multi: local PII rules only

[`sql-safe-mcp.example-multi.yaml`](../sql-safe-mcp.example-multi.yaml) keeps PII rules next to
each `all_pii_safe` alias. It has no top-level `pii_rules`, so no rule is silently inherited by another
server. The SQL Server rule shows an optional `schema`; the MySQL rule omits it because MySQL and
MariaDB reject `schema` in PII rules. Each PII-safe alias names a different environment key.

### Shared: reusable PII rules and operating settings

[`sql-safe-mcp.example-shared.yaml`](../sql-safe-mcp.example-shared.yaml) is the full reference
template. Its unnamed shared group applies to every PII-safe alias, while `users_pii` applies only
where the exact name appears in `pii.include`. The file also shows the complete runtime-limit set,
their accepted ranges, the allowed log levels, and local rules that are added after shared ones.

## Locating and checking the file

The server reads `--config`, else `SQL_SAFE_MCP_CONFIG`, else `sql-safe-mcp.yaml` in the working
directory. Validate the file and its environment without connecting to any database:

```bash
sql-safe-mcp --check-config
```

Errors name the missing or invalid setting without printing a URL, key, or secret.

## Verifying PII rules against the real schema

A misspelled table or column in a PII rule silently protects nothing. Before starting the server,
check the rules against the live databases:

```bash
sql-safe-mcp --verify-pii-rules
sql-safe-mcp --verify-pii-rules --strict
```

For every `all_pii_safe` alias the command connects to each database named in its rules (to every
visible database for `"*"`), reflects tables and columns, and prints to stderr, per rule, how many
tables and columns it matched. `pii.exposed_columns` and `pii.deny` entries are checked the same
way, so a misspelled `deny` entry that would silently deny nothing is reported. An entry that
matches nothing prints `WARNING`; with `--strict` the
command then exits 2. A database that cannot be reached or reflected prints `ERROR` and exits 2
with or without `--strict`. Only object names are printed, never URLs, keys, or rows.

The command also prints `WARNING: unprotected column looks personal` for every column no rule
protects whose name contains one of (with `deny-by-default`, only columns in `exposed_columns`
are checked, and denied columns never are): `email`, `phone`, `mobile`, `ssn`, `passport`, `dob`,
`birth`, `address`, `zip`, `postal`, `name`, `diagnos`, `icd`, `mrn`, `guardian`, `ip_`, `device`,
`photo`, `notes`. This list is fixed and name-based: it misses misspelled or opaque names, flags
harmless ones, and never changes the exit code. It is a hint, not a guarantee that no personal
data is exposed.

## Top-level keys

| Key | Meaning |
|---|---|
| `version` | Required. Must be `1`. |
| `servers` | Required. A non-empty map of alias to server settings. |
| `runtime` | Optional limits; see [Runtime limits](#runtime-limits). |
| `logging` | Optional; see [Logging](#logging). |

Unknown keys anywhere in the file are a startup error.

## Servers

```yaml
version: 1
servers:
  reporting:
    engine: sqlserver
    access_level: metadata
    connection_url: "${REPORTING_SQL_URL}"
```

| Key | Meaning |
|---|---|
| alias (the map key) | Letters, digits, `.`, `_`, `-`; starts with a letter or digit. This is what the agent passes as `server`. |
| `engine` | `sqlserver` (`mssql+pyodbc`), `mysql` or `mariadb` (both `mysql+pymysql`). MySQL and MariaDB have no schema level: `schema` is always `null`, and a `pii` rule for them must not set `schema` (the table is matched by `database` and `table`). |
| `access_level` | `metadata` (default: navigation and table structure), `meta_and_code` (also stored procedures), or `all_pii_safe` (also `execute_sql`). `pii_safe` is not accepted. |
| `connection_url` | Required. A SQLAlchemy `mssql+pyodbc://` (SQL Server) or `mysql+pymysql://` (MySQL, MariaDB) URL whose dialect must match `engine`. Treated as a secret. |
| `pii_key_env` | Required for `all_pii_safe`, forbidden otherwise. The name of the environment variable holding the alias key; matches `^[A-Z_][A-Z0-9_]*$`. |
| `pii` | Required for `all_pii_safe`, forbidden otherwise. Holds `rules`; see [PII rules](#pii-rules). |

### `connection_url`

`connection_url` tells SQLAlchemy which driver to use and where the database lives. Its general
shape is:

```text
dialect+driver://user:password@host:port/database?option=value&another_option=value
```

`dialect+driver` is fixed by `engine`; `user`, `password`, `host`, `port`, and `database` identify
the database; and the optional part after `?` contains driver-specific `name=value` options joined
with `&`. Keep the complete URL in a secret environment variable, or construct it from individual
environment variables as below. Do not put credentials in the YAML file.

#### SQL Server (`engine: sqlserver`)

SQL Server requires the exact `mssql+pyodbc` dialect. `pyodbc` connects through an installed
Microsoft ODBC driver; this project supports Microsoft ODBC Driver 18 for SQL Server.

```yaml
connection_url: >-
  mssql+pyodbc://${SQLSERVER_USER}:${SQLSERVER_PASSWORD}
  @${SQLSERVER_HOST}:${SQLSERVER_PORT}/${SQLSERVER_DATABASE}
  ?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes&TrustServerCertificate=no
```

| Part or option | Meaning |
|---|---|
| `SQLSERVER_USER`, `SQLSERVER_PASSWORD` | SQL Server login and its password. These placeholders are URL-encoded during substitution, so characters such as `@` or `/` in a password are safe. |
| `SQLSERVER_HOST` | DNS name or IP address of the SQL Server. Keep it separate from the port. |
| `SQLSERVER_PORT` | TCP port, for example `1433`. Omit `:${SQLSERVER_PORT}` from the URL when the driver's default or instance configuration should choose the port. |
| `SQLSERVER_DATABASE` | Database to connect to, for example `master` or `Reporting`. Database permissions still control what the server can read. |
| `driver` | Required ODBC driver name. It must name an installed driver; spaces are written as `+` because this is a URL. `ODBC+Driver+18+for+SQL+Server` is the usual value for Driver 18. |
| `Encrypt=yes` | Requests an encrypted connection. Keep it enabled for normal deployments. |
| `TrustServerCertificate=no` | Requires certificate validation. Set it to `yes` only when a controlled development environment deliberately uses a certificate that cannot be validated. |

Other query options are ODBC connection attributes. Use only options required by the server or
your organization's connection policy; they remain part of the secret URL when using a whole-value
environment variable.

#### MySQL or MariaDB (`engine: mysql` or `engine: mariadb`)

Both engines require the exact `mysql+pymysql` dialect. The engine name must describe the actual
server, even though both use the same PyMySQL driver.

```yaml
connection_url: >-
  mysql+pymysql://${MYSQL_USER}:${MYSQL_PASSWORD}
  @${MYSQL_HOST}:${MYSQL_PORT}/${MYSQL_DATABASE}
  ?charset=utf8mb4&connect_timeout=10
```

| Part or option | Meaning |
|---|---|
| `MYSQL_USER`, `MYSQL_PASSWORD` | MySQL/MariaDB login and password. Embedded placeholders are URL-encoded during substitution. |
| `MYSQL_HOST` | DNS name or IP address of the database server. Keep it separate from the port. |
| `MYSQL_PORT` | TCP port, commonly `3306`. Omit `:${MYSQL_PORT}` when the driver's default port should be used. |
| `MYSQL_DATABASE` | Database (catalog) to connect to. MySQL and MariaDB have no separate schema level in this server. |
| `charset=utf8mb4` | Requests the UTF-8 character set that supports the full Unicode range. Change it only when the database is configured for a different required character set. |
| `connect_timeout=10` | Limits the driver's connection attempt to 10 seconds. Use a positive number appropriate for the network; it is separate from the YAML `runtime.pool_timeout_seconds`, which limits waiting for a pooled connection. |

For either form, if a URL part must be literal rather than a placeholder, URL-encode reserved
characters in that part. The following [Placeholders](#placeholders) section explains the
whole-value and embedded-placeholder forms, including why `host` and `port` must be separate.

### Placeholders

`${NAME}` reads the environment variable `NAME`. A placeholder that occupies the whole
`connection_url` may hold a complete SQLAlchemy URL. A placeholder embedded in a longer URL is
URL-encoded before substitution, so a password containing `@` or `/` is safe. A missing variable is
a startup error.

Because of that encoding, a variable must hold one URL part. Keep the host and the port in separate
variables; a `host:port` value would have its `:` encoded and the driver would look for a host that
does not exist, then fail after its login timeout. A startup error catches an encoded character in
the host:

```yaml
# DEV_SQL_HOST=10.12.11.107  DEV_SQL_PORT=1433
connection_url: "mssql+pyodbc://${DEV_SQL_USER}:${DEV_SQL_PASSWORD}@${DEV_SQL_HOST}:${DEV_SQL_PORT}/master?driver=ODBC+Driver+18+for+SQL+Server"
```


## All-PII-safe servers

`all_pii_safe` enables `execute_sql` for a server alias. Such an alias requires its own base64-encoded 32-byte key in the variable named by `pii_key_env`,
plus at least one effective PII rule. Effective rules can be local under `pii.rules`, inherited
from an unnamed default set, or explicitly included from named shared sets.

```
sql-safe-mcp --gen-pii-key
```

The command prints one key to stdout and exits without loading the configuration or connecting to a
database. Store that value in the secret environment or configuration used by your MCP host under
the variable named by `pii_key_env`; never put it in the YAML file. To generate a separate key for
each of several aliases, pass a positive count. The command prints exactly that many keys, one per
line:

```
sql-safe-mcp --gen-pii-key 3
```

A key reused by two aliases is rejected. Tokens authenticate the alias as associated data, so
they cannot cross aliases even if keys are duplicated outside normal config loading. Rotating a key
or renaming an alias will invalidate existing tokens. `metadata` and `meta_and_code` servers must
not set `pii_key_env` or `pii`.

### Token lifetime

`runtime.token_ttl_seconds` is off by default: a token stays valid until its key changes. When
set, each new token records its issue time in whole seconds inside the encrypted payload, and a
token older than the limit is rejected as `INVALID_PII_TOKEN`. A token issued before the limit was
set has no issue time and is rejected too, so enabling a TTL invalidates existing tokens. Turning
the TTL off again accepts every token sealed with the current key.

### PII rules

Each `pii.rules` entry protects columns of tables selected by one table pattern:

| Key | Meaning |
|---|---|
| `database` | Required. An exact database name, or the whole value `"*"` for every database. |
| `schema` | Optional, SQL Server only. Omitted means the table is protected in every schema. Must not be set for `mysql` or `mariadb`. |
| `table` | Required shell-glob pattern, matched case-insensitively against the complete resolved table name. |
| `columns` | Required. A non-empty list of column names, unique ignoring case. |

`table` uses standard shell-glob syntax: `*` matches zero or more characters, `?` exactly one,
`[abc]` a character class, `[a-z]` a range, and `[!abc]` a negated class. It is always a full
match, not a substring match. `database`, `schema`, and `columns` do not become patterns; their
existing exact matching rules remain unchanged. Names match case-insensitively. Only listed columns
are protected, so list every column that holds personal data. On MySQL and MariaDB the database is
the catalog: `database` is the MySQL database name and the rule has no `schema`.

Migration note: an existing exact table name containing `?`, `[` or `]` is now interpreted as a
glob. Use `[*]`, `[?]`, `[[]`, and `[]]` to match literal `*`, `?`, `[`, and `]`, respectively.

For example, `Customer*` matches `Customer` and `CustomerArchive`; `Users[0-9]?` matches
`Users1a` and `Users42`; and `Audit[!0-9]` matches `AuditX` but not `Audit7`. To match literal
glob characters, use patterns such as `Legacy[?]` for the table `Legacy?` and
`Report[[]2026[]]` for `Report[2026]`.

SQL Server, every database, one table:

```yaml
pii:
  rules:
    - database: "*"
      schema: dbo
      table: Users
      columns: [Email, FirstName, LastName]
```

SQL Server, several tables, one of them limited to a single database:

```yaml
pii:
  rules:
    - database: "*"
      schema: dbo
      table: Users
      columns: [Email, Phone]
    - database: Billing
      schema: dbo
      table: Cards
      columns: [HolderName, LastFour]
    - database: Billing
      schema: audit
      table: Logins
      columns: [IpAddress]
```

SQL Server, `schema` omitted, so `Customers` is protected in every schema:

```yaml
pii:
  rules:
    - database: Crm
      table: Customers
      columns: [Email, BirthDate]
```

MySQL or MariaDB (no `schema`):

```yaml
pii:
  rules:
    - database: shop
      table: customers
      columns: [email, full_name, address]
    - database: "*"
      table: sessions
      columns: [ip_address]
```

These are startup errors:

```yaml
pii:
  rules:
    - database: shop*
      table: customers          # database is exact or the whole "*"
      columns: [email]
    - database: shop
      schema: dbo              # invalid for mysql and mariadb
      table: customers
      columns: [email, EMAIL]  # duplicate column
```

### Token domains

A token is bound to its server alias and to a token domain. By default the domain is the alias, so
a token from any protected column of an alias can be compared with any other protected column of
that alias (for example to join on a protected key). Add `domain` to a `pii.rules` entry to
narrow this: a token returned for a column in domain `contact` is accepted only in a predicate
on a column of domain `contact`; anywhere else it is rejected with `INVALID_PII_TOKEN`, the same
error as a forged token. For health data prefer one domain per entity (for example `patient`,
`guardian`) so a token cannot be replayed across unrelated columns.

`domain` uses the alias character set (letters, digits, `.`, `_`, `-`; starts with a letter or
digit) and is allowed only on `pii.rules`, not on `exposed_columns` or `deny`. Rules without
`domain` keep the alias-wide domain. A
`domain` equal to the alias is the same as no `domain`. If rules of different domains match the
same column, `execute_sql` rejects any query that touches that column with `QUERY_REJECTED`
("pii rules of different token domains match the same column"); this is detected per query
because it depends on the database schema. Adding, changing, or removing a `domain` invalidates
tokens already issued for the affected columns.

```yaml
pii:
  rules:
    - {database: "*", table: Patients, columns: [Email, Phone], domain: contact}
    - {database: "*", table: Billing, columns: [Amount], domain: money}
```

### Deny-by-default mode and the `deny` list

By default (`pii.mode: protect`) only columns listed in `pii.rules` are protected. For data where
an unlisted column is itself a risk (medical records, free-text notes), set
`pii.mode: deny-by-default`. Then every column is protected (returned as a token, compared only
with tokens) unless `pii.exposed_columns` lists it; `SELECT *` returns tokens for the unlisted
columns rather than an error. `pii.rules` still protect columns and `pii.exposed_columns` has no
effect in `protect` mode. Configurations without `mode` behave as before.

`pii.deny` lists columns that cannot be referenced at all, even as tokens: any use in a
projection, `WHERE`, `ORDER BY`, `JOIN`, or a `*` expansion is rejected with `QUERY_REJECTED`
and the reason "a denied column cannot be referenced". `deny` wins over `rules` and
`exposed_columns`. `COUNT(*)` does not reference columns, so it is unaffected.

`exposed_columns` and `deny` entries use the `database`, `schema`, `table`, and `columns` keys
described above, except that `database` is optional and defaults to `"*"`. `columns: ["*"]` is
allowed only in `deny` and denies every column of the matching tables. A server using
`deny-by-default` must be `all_pii_safe`. `include`d shared sets contribute `rules`,
`exposed_columns`, and `deny` in the same order as `rules`; `mode` is set per alias only.

A deny-by-default alias for a pediatric database:

```yaml
servers:
  peds_ro:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: "${PEDS_SQL_URL}"
    pii_key_env: PEDS_PII_KEY
    pii:
      mode: deny-by-default
      exposed_columns: # open columns; everything else is a token
        - table: Visits
          columns: [VisitId, DepartmentCode, VisitYear]
      deny: # unreachable even as a token
        - table: "*"
          columns: [Notes, Anamnesis, Attachment]
```

The database login should additionally carry column-level `DENY` on free-text columns; this
setting is defense in depth, not a replacement for database permissions.

### Shared PII rule sets

Top-level `pii_rules` is optional. If present, it is a non-empty sequence of strict groups with a
non-empty `rules` list. A group without `name` is the one unnamed default; at most one may exist,
and its rules apply to every `all_pii_safe` alias. A named group is inactive until an alias lists its
exact, case-sensitive name in `pii.include`. Unused named groups are allowed.

`include` must be a YAML sequence, not a comma-separated string. Unknown names and repeated names
are startup errors. The effective list is deterministic: unnamed default rules first, named groups
in the order written in `include`, then local `pii.rules`. Rules are a union: they are neither
overridden nor deduplicated. The loader flattens this list before the server starts, so MCP tools,
tokens, and SQL policy do not expose shared-set concepts.

```yaml
pii_rules:
  - rules: # optional unnamed default: every all_pii_safe alias receives this rule
      - database: "*"
        table: "Audit*"
        columns: [IpAddress]
  - name: users_pii
    rules:
      - database: "*"
        schema: dbo
        table: "Users[0-9]?"
        columns: [Email, Phone]

servers:
  app:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: "${APP_SQL_URL}"
    pii_key_env: APP_PII_KEY
    pii:
      include: [users_pii]
      rules: # local rules follow default and included rules
        - database: Billing
          table: Cards
          columns: [HolderName]
```

A `all_pii_safe` alias may omit `pii` only when the unnamed default yields at least one rule. The
legacy local-only `pii.rules` form remains valid. Engine restrictions are checked after resolution:
a shared rule with `schema` may be used by SQL Server but makes a MySQL/MariaDB alias that includes
it invalid. A global rule set alone never changes a `metadata` or `meta_and_code` alias; those
aliases still cannot configure `pii_key_env`, `pii.include`, or `pii.rules`.

## Runtime limits

Optional, under `runtime:`. A value outside its range is a startup error.

| Setting | Default | Range |
|---|---|---|
| `max_concurrent_db_operations` | 8 | 1-128 |
| `engine_cache_size` | 32 | 1-1024 |
| `pool_size` | 2 | 1-32 |
| `max_overflow` | 2 | 0-64 |
| `pool_timeout_seconds` | 10 | 1-300 |
| `statement_timeout_seconds` | 30 | 1-3600 |
| `max_definition_chars` | 262144 | 1024-10000000 |
| `token_ttl_seconds` | none (tokens do not expire) | 1-315360000; see [Token lifetime](#token-lifetime) |
| `default_max_rows` | 200 | 1-100000, at most `hard_max_rows` |
| `hard_max_rows` | 1000 | 1-100000 |
| `max_sql_chars` | 65536 | 256-1000000 |
| `max_ast_nodes` | 2000 | 10-100000 |
| `max_joins` | 8 | 0-100 |
| `max_in_list_items` | 500 | 1-100000 |

The last four bound the SQL accepted by `execute_sql`; a query at the limit is accepted and one
above it is rejected.

## Logging

Optional, under `logging:`. The server writes to stderr only, using the standard `logging` module;
stdout carries MCP messages and nothing else. Claude Desktop keeps stderr in its MCP log, and other
hosts show it in their own MCP log or console.

```yaml
logging:
  level: INFO # DEBUG, INFO, WARNING or ERROR (uppercase)
  audit: false # true writes one audit line per execute_sql call
```

| Level | What you see |
|---|---|
| `INFO` (default) | Each database connection (`connect ok` or `connect failed`, with server alias, database, and `elapsed_ms`) and each tool operation (`operation ok` or `operation failed`, with the tool name). |
| `DEBUG` | Also engine creation and eviction. |
| `WARNING`, `ERROR` | Failures only. |

A failed connection or operation logs the driver error class, the SQLSTATE or numeric code, and the
driver message. The connection URL's user name and password are replaced with `***` and its host with the
server alias in that message. Quoted literals (`'…'`, `N'…'`, `"…"`) become `'***'`, digit runs of six or
more become `***`, control characters are replaced, and long messages are truncated. A failed `execute_sql`
logs only the class and the code, never the message, because drivers echo the offending value. A `TIMEOUT` or
`CONNECTION_FAILED` error shown to the caller carries a `Reference`; the same value appears as
`reference=` on the matching log line.

Reading a failure: `connect failed ... elapsed_ms=` near the login timeout points at reaching or
logging in to the server, while `operation failed` after a `connect ok` points at the query itself.

Connection URLs, credentials, keys, tokens, SQL text, bind values, and result rows are never
logged. SQLAlchemy's own statement logging stays off at every level.

### Audit log

With `audit: true` (default `false`), every `execute_sql` call that reaches the database layer writes
one `INFO` line to the `sql_safe_mcp.audit` logger, on stderr with the rest, whatever `level` is:

```text
audit server=secure database=app tables=dbo.Users columns=dbo.Users.Email,dbo.Users.Id protected=1 row_count=2 truncated=False elapsed_ms=12 reference=0f3c9a1e5b7d4c2a8e6f1b3d5a7c9e0f
```

`tables` and `columns` list every table and column the query reads, including those used only in
`WHERE` or `JOIN`, as reflected `schema.table[.column]` names, sorted. `protected` is the number of
returned columns that are PII tokens. `row_count` and `truncated` describe the result. A field with
nothing to report shows `-`. `reference` is a fresh identifier for the line; when the call failed
it is the error's `Reference`, if the error has one.

A failed call writes the same line with `code=<ErrorCode>` in place of `row_count` and `truncated`.
A query rejected before its tables were resolved shows `tables=- columns=- protected=-`. A call
refused for the server's access level or alias never reaches the database layer and is not audited.

The line holds names and counts only: never SQL text, bind values, result rows, or tokens. Any
character other than a letter, digit, or one of `.$#@-` in a name, including the caller-supplied
`database`, is shown as `?`. The line carries no MCP client identity, because the host does not
pass a verified one.
