# Security policy

## Supported versions

Only the latest release receives security fixes. Upgrade to the newest version from
[PyPI](https://pypi.org/project/sql-safe-mcp/) or the
[Releases](https://github.com/proprock/sql-safe-mcp/releases) page.

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub's private vulnerability reporting
instead:

**[Report a vulnerability](https://github.com/proprock/sql-safe-mcp/security/advisories/new)**

Please include the affected version, what you observed, the steps to reproduce it against a
disposable, non-production database, and a suggested fix if you have one. Never include a real
connection URL, credential, PII key, token, or customer data in a report; redact them.

## What to expect

This is a small project with one maintainer, so timelines are best effort:

- an acknowledgment within about 7 days;
- an assessment and a plan once the report is understood;
- coordinated disclosure: the fix ships in a release before details are made public, and the
  reporter is credited in the advisory unless they prefer not to be.

There is no fixed patch deadline; severity decides the order of work.

## In scope

Problems in this server's own code, such as:

- a connection URL, credential, PII key, token, SQL bind value, or result row reaching a log, a
  startup message, or a model-visible error;
- the server executing SQL that did not come from a `ValidatedQuery`, or any tool changing data;
- a name or filter reaching SQL by concatenation instead of a bound or quoted identifier;
- a PII token that decrypts under another server alias, or protected values leaving an `all_pii_safe`
  server in the clear;
- a configuration that is accepted but weaker than it declares, such as a duplicated PII key;
- an unknown or unresolved construct that is allowed instead of refused;
- partial disclosure of a protected value beyond what
  [security-model.md](docs/security-model.md) documents as residual, for example a token whose
  length reveals more than its 32-byte bucket, or tokens of equal values that match offline.

## Out of scope

- Vulnerabilities in SQL Server, ODBC drivers, or third-party dependencies (report those upstream).
- An attacker who already holds the database credentials or PII keys, or controls the host that
  runs the server.
- What the configured database account is allowed to do; this server never widens or narrows
  database permissions.
- PII outside the columns you configured. Protection covers configured columns only.
- Prompt injection carried in database content. Table data, stored procedure bodies, and metadata
  are untrusted input to the agent that reads them; treat them that way.

How the server protects data, and the evidence behind it, is described in
[security-model.md](docs/security-model.md).
