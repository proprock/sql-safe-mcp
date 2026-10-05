<div align="center">

# sql-safe-mcp

A PII-safe, read-only MCP server for coding agents working with SQL Server, MySQL and MariaDB:
schema knowledge and safe queries without write-capable tools or plaintext exposure of configured
PII columns.

[![CI](https://github.com/proprock/sql-safe-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/proprock/sql-safe-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/proprock/sql-safe-mcp)](https://github.com/proprock/sql-safe-mcp/releases)
[![PyPI Version](https://img.shields.io/pypi/v/sql-safe-mcp?cacheSeconds=3600)](https://pypi.org/project/sql-safe-mcp/)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[![Model Context Protocol compatible](https://img.shields.io/badge/Model_Context_Protocol-compatible-000000?logo=modelcontextprotocol&logoColor=white)](https://modelcontextprotocol.io)
[![MCP Registry: io.github.proprock/sql-safe-mcp](https://img.shields.io/badge/MCP_Registry-io.github.proprock%2Fsql--safe--mcp-000000?logo=modelcontextprotocol&logoColor=white)](server.json)

<img src="https://raw.githubusercontent.com/proprock/sql-safe-mcp/master/images/luna-guard.jpg" alt="Read the data. Protect the identity." width="760">

<i>Read the data. Protect the identity.</i>

</div>

<!-- mcp-name: io.github.proprock/sql-safe-mcp -->

Give a coding agent the schema knowledge it needs to write correct code - servers, databases,
tables, columns, keys, indexes, and stored procedures. On aliases you mark `all_pii_safe`, it can also
query real rows while configured personal data stays hidden behind authenticated tokens.

## PII-safe by default. Read-only by design.

- **PII-safe by default** - on an `all_pii_safe` server, the columns you configure come back as
  alias-bound, authenticated tokens (`pii:v1:...`), never as plaintext. An agent can still
  project, count, and filter on them with `=` and `IN` using tokens it was given, so it can follow
  a record without reading it. Tokens do not work on another server alias or with another key.
- **Read-only by construction** - seven tools, all annotated read-only. No tool writes data, and
  the server never executes SQL an agent wrote: metadata comes from SQLAlchemy Inspector and fixed
  catalog queries, and `execute_sql` runs only a validated, regenerated `SELECT`.
- **Multiple servers, isolated policies** - one MCP process can expose multiple named SQL Server,
  MySQL, and MariaDB instances. Each alias has its own connection, access level, and, when enabled,
  PII key and protection rules. Every database operation targets an explicit alias; there is no
  network discovery.

## Operational safeguards

- **Fails closed** - SQL validation is an allowlist. Unknown syntax, unresolved lineage, and
  unsupported protected-value types are refused, not guessed at. The verification evidence is in
  the [security model](docs/security-model.md).
- **Least access first** - `access_level: metadata` (the default) exposes database navigation and
  table structure; `meta_and_code` additionally exposes stored procedures; `execute_sql` needs an
  explicit `all_pii_safe` alias with its own key. Database permissions stay the primary control,
  so use a least-privilege login.
- **Secrets stay out of sight** - connection URLs live in YAML with `${NAME}` placeholders resolved
  from the environment. They never appear in logs or model-visible errors.
- **Compact, predictable output** - object-rooted results with stable sorting, literal
  case-insensitive name filters, and stored procedure lists that do not expand definitions.
- **Errors an agent can act on** - an ambiguous name lists the candidate schemas. Errors never
  contain connection details, credentials, keys, tokens, or rows.
- **Tested against attacks, not just examples** - the SQL and PII boundary is checked with an
  adversarial corpus of hostile statements, property-based tests (token isolation, tamper
  resistance), a live attack run against a really writable login with before/after snapshots, and
  mutation testing. Results are in
  [Verification of the SQL boundary](docs/security-model.md#verification-of-the-sql-boundary).
- **Diagnosable failures** - a timeout or connection error carries a `Reference`, and the stderr
  log records the connection stage, elapsed time, and driver error for the same reference, with
  credentials removed. See [Logging](docs/configuration.md#logging).

| Tool | Access | Purpose |
|---|---|---|
| `list_servers` | 🟢 read | Configured server aliases |
| `list_databases` | 🟢 read | Databases visible to the credentials |
| `list_tables` | 🟢 read | Base tables, filtered by schema or name |
| `get_table_definition` | 🟢 read | Columns, keys, constraints, and indexes of one table |
| `list_stored_procedures` | 🟢 read | Stored procedures, without definitions; requires `meta_and_code` or `all_pii_safe` |
| `get_stored_procedure` | 🟢 read | The definition of one stored procedure; requires `meta_and_code` or `all_pii_safe` |
| `execute_sql` | 🟢 read | One restricted `SELECT` on an `all_pii_safe` server; protected columns return tokens |

> [!NOTE]
> **Status:** SQL Server supports every tool. MySQL and MariaDB (`engine: mysql` or `mariadb`,
> `mysql+pymysql` URLs) support every tool too. `schema` is always `null` there because the
> database is the catalog, and `execute_sql` uses `LIMIT` instead of `TOP`. See
> [architecture.md](docs/architecture.md).

## Quick start

### Install

```bash
uvx sql-safe-mcp
```

or

```bash
pip install sql-safe-mcp
```

Pin a version when you want a fixed surface: `uvx sql-safe-mcp==1.5.2`.

Requires Python 3.12–3.14, [uv](https://docs.astral.sh/uv/) (or `pip`), and
[Microsoft ODBC Driver 18 for SQL Server](https://learn.microsoft.com/sql/connect/odbc/download-odbc-driver-for-sql-server)
when you connect to SQL Server. MySQL and MariaDB use the bundled PyMySQL driver and need nothing
else.

Verified against SQL Server 2022, MySQL 8.4, and MariaDB 11.4 (see [checks.md](docs/checks.md)).

<details>
<summary><b>Or you can even ask an agent to install it</b></summary>

```text
Install sql-safe-mcp as a stdio MCP server.
Ask whether to install it for this project/workspace or at user level. Then:
detect and preserve the host's existing MCP config;
configure the server to run via uvx sql-safe-mcp;
create a YAML config template with env placeholders only;
add SQL_SAFE_MCP_CONFIG;
report the env variables the user must set.
Do not store secrets or connection data in tracked files or output. Validate with
sql-safe-mcp --check-config once variables are available.
```

</details>

### Configure server

Copy [sql-safe-mcp.example-simple.yaml](sql-safe-mcp.example-simple.yaml) to
`sql-safe-mcp.yaml`. This smallest configuration exposes schema metadata from one SQL Server
instance and does not allow row queries. Keep the complete connection URL in an environment
variable:

```yaml
version: 1
servers:
  reporting:
    engine: sqlserver
    access_level: metadata
    connection_url: "${REPORTING_SQL_URL}"
```

Here `reporting` is the value an agent passes as `server`. A missing variable, or an `engine` that
does not match the URL dialect, stops the MCP server at startup. For multiple servers, local PII
rules, shared PII rule sets, logging, and runtime limits, use the commented examples in the
[configuration reference](docs/configuration.md#complete-examples).

### Check the configuration

After defining every environment variable referenced by the YAML file, point the server at it with
`SQL_SAFE_MCP_CONFIG` (or `--config`) and check it without connecting to any database:

```bash
SQL_SAFE_MCP_CONFIG=sql-safe-mcp.yaml uvx sql-safe-mcp --check-config
```

Configuration is validated at startup, and an error names the problem without printing a URL or
secret. Keep credentials in the host's own configuration and never commit them. The server acts
with the database account's permissions, so use a dedicated login with the least access the job
needs.

### Connect an MCP client

Every client configuration needs `SQL_SAFE_MCP_CONFIG` plus the environment variables referenced
by your YAML file. Keep connection URLs and PII keys in the MCP host's environment or
configuration, never in the YAML file or other tracked files.

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add --env SQL_SAFE_MCP_CONFIG=/path/to/sql-safe-mcp.yaml --env REPORTING_SQL_URL=mssql+pyodbc://... --transport stdio sql-safe -- uvx sql-safe-mcp
```

Put at least one other option between the last `--env` and the server name, as above. Otherwise,
the CLI reads the name as another `KEY=value` pair.

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sql-safe": {
      "command": "uvx",
      "args": ["sql-safe-mcp"],
      "env": {
        "SQL_SAFE_MCP_CONFIG": "/path/to/sql-safe-mcp.yaml",
        "REPORTING_SQL_URL": "mssql+pyodbc://..."
      }
    }
  }
}
```

</details>

<details>
<summary><b>Codex CLI</b></summary>

```bash
codex mcp add sql-safe --env SQL_SAFE_MCP_CONFIG=/path/to/sql-safe-mcp.yaml --env REPORTING_SQL_URL=mssql+pyodbc://... -- uvx sql-safe-mcp
```

</details>

<details>
<summary><b>Any other stdio host</b></summary>

Use command `uvx`, argument `sql-safe-mcp`, and set `SQL_SAFE_MCP_CONFIG` plus every environment
variable referenced by the configuration file. The server writes MCP messages to stdout and logs
only to stderr.

</details>

## PII-safe queries

`execute_sql` on the `billing` alias allows one restricted `SELECT`. For example, these arguments:

```json
{
  "server": "billing",
  "database": "Billing",
  "sql": "SELECT CustomerId, Email FROM dbo.Customers"
}
```

can return a row such as `[42, "pii:v1:..."]`: the agent can follow the customer without reading
the email address. A token is accepted only in `=` and `IN` predicates on the same server alias.
If `FirstName` is protected, `SELECT FirstName FROM Users WHERE FirstName = 'Alice'` is rejected
before it reaches the database. Filter protected columns only with authentic `pii:v1:...` tokens
returned by `execute_sql` for the same alias; a matching prefix alone is not enough. Each token is
authenticated and alias-bound, then validated and converted to a bound database value.
Protection covers the columns you list, so list every column that holds personal data.

## Documentation

- [Configuration reference](docs/configuration.md) - aliases, connection URLs, PII rules, runtime
  limits, and logging.
- [Tool reference](docs/tools.md) - arguments, responses, errors, and the accepted SQL subset.
- [Security model](docs/security-model.md) - trust boundaries, guarantees, limitations, and verification.
- [Checks](docs/checks.md) - local, integration, and security verification commands.

## Security

The MCP caller, SQL input, database metadata, rows, and tokens are untrusted. Database permissions
remain the primary authorization control - this server never widens them. Read the full
[security model](docs/security-model.md), including its limitations and verification evidence. To report
a vulnerability, use the private channel in [SECURITY.md](SECURITY.md).

## Contributing

Setup, checks, the test commands, the branch and commit conventions, and the release model are in
[CONTRIBUTING.md](CONTRIBUTING.md). Changes that affect someone running the server are recorded in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).
