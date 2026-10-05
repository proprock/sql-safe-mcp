# Security model

How sql-safe-mcp protects data, and the evidence behind it. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Trust boundary

The MCP caller, SQL input, database metadata, rows, and tokens are untrusted. The operator, process
environment, host OS, configured database server, and credentials form the trusted boundary.
Database credentials remain the primary authorization control.

PII protection covers only configured columns. Each `all_pii_safe` server alias has a unique AES-256
key and a distinct authenticated token domain. Tokens are bearer secrets and must not be logged.

SQL validation is an allowlist. Unknown syntax, cross-database names, unresolved tables or columns,
unsupported lineage, and unsupported protected-value types fail closed. The executor accepts only a
`ValidatedQuery` created after the final AST check.

Diagnostic logs go to stderr. A logged database error is limited to its class, SQLSTATE or code,
and message; the message has the connection URL's user name and password replaced with `***`,
its host replaced with the server alias, and its control characters replaced.

Errors must explain the safe cause and, when known, the caller's corrective action. Logs and
model-visible errors must not expose URLs, credentials, keys, tokens, SQL bind values, database
metadata, or result rows.

Before merging security changes, run the adversarial, property-based, integration, and mutation
gates described in [checks.md](checks.md). Every security-relaxing non-equivalent mutant must be
killed.

## Verification of the SQL boundary

`execute_sql` is verified by layered evidence, all described in [checks.md](checks.md):

- an adversarial corpus of 300 hostile statements (`tests/security/corpus`) that must fail with
  their expected code without reaching the database;
- Hypothesis properties (`security-fast` on every milestone/release security gate,
  `security-deep` before a milestone merge)
  covering forbidden constructs, formatting and alias invariance, lineage, token isolation and
  tamper resistance, and "only validated SQL is ever executed";
- a MySQL/MariaDB corpus (`tests/security/corpus_mysql`) plus the T-SQL corpus replayed on the
  `mysql` dialect, and live `execute_sql` tests against MySQL and MariaDB;
- a live attack fixture that runs the whole corpus against SQL Server with a really writable
  login, compares a snapshot of every object and row before and after, and records every statement
  that reached the driver;
- mutation testing of `security/*.py` and `config.py`.

MySQL sessions drop `NO_BACKSLASH_ESCAPES` on connect so the generated string escaping means what
the AST means; the live suite proves this with the mode enabled server-wide.

Comments in the caller's SQL are removed before generation, so no caller-controlled text is
executed except through the validated AST, and rejection reasons come from a fixed catalog.

### Equivalent mutants

The last complete mutation run (Linux, mutmut 3.8, 1454 mutants, after the mysql dialect work)
killed 1413 mutants, with no timeouts and no unclassified survivors. The 41 survivors are
equivalent to the original code:

| Location | Mutation | Why it cannot change behavior |
|---|---|---|
| `validated_query._to_positional` (2) | `replace(marker, dialect.bind_marker, 1)` with the count omitted or 2 | Markers are unique random strings and the guard `len(found) == len(markers) and set(found) == set(markers)` proves each occurs exactly once. |
| `executor._encode` (1) | `.decode("ascii")` as `"ASCII"` | Python codec names are case-insensitive aliases. |
| `tokens._reject_constant` (4) | message text | The `ValueError` is raised inside `json.loads` and swallowed by `TokenCodec.decrypt`, which always raises the fixed `INVALID_PII_TOKEN` error; the text is never observed. |
| `tokens._encode_float` (6) | `or` as `and`, `float("INF")`, `float("-INF")`, three message texts | `json.dumps(..., allow_nan=False)` rejects NaN and infinities right after, and `encrypt` maps that `ValueError` to the same unsupported-value error. `float("INF") == float("inf")`. |
| `schema.SchemaCache.put` (1) | `popitem(last=None)` | `None` is falsy, identical to `last=False`. |
| `schema.ReflectedCatalog.list_tables`, `.columns` (4) | cache-key tag string | The tag only distinguishes the two key shapes, which already differ in length; every key still carries alias and database (tested). |
| `lineage._collect` (3) | `zip(..., strict=None/False/omitted)` | The `len(nodes) != len(schemas)` guard immediately above raises first (tested), so the lengths are always equal. |
| `lineage._analyze_projections` (1) | `... or True` | `Expr.alias` is `""` for every non-`Alias` node. |
| `lineage._cross_check` (9) | column type value, `expand_stars` omitted/`True`/`None`, `validate_qualify_columns` omitted, `cast(None, ...)` | This is a second opinion; column types are unused, the checked query contains no stars, `validate_qualify_columns` defaults to `True`, and `cast` is a runtime no-op. Its behavior with the schema and validation enabled is pinned by direct tests. |
| `policy._token_site` (1) | `not isinstance(node, Literal) and not node.is_string` | The third disjunct (`not startswith(PREFIX)`) still rejects every non-literal and non-string node, and accepts exactly the same token literals. |
| `config._expand_connection_url` (1) | `quote(..., safe="XXXX")` | `X` is unreserved and is never escaped. |
| `config._validation_summary` (6) | `errors()` flags `include_url`, `include_context`, `include_input` | The summary reads only `loc` and `msg`; the flags only add keys that are never read. |
| `config.load_config` (2) | `read_text(encoding="UTF-8")` and `encoding=None` | The first is an alias. The second equals UTF-8 only where the default locale is UTF-8 (Linux/WSL, where mutation runs); on Windows `test_non_ascii_values_survive_loading` fails against it. |

Message text of rejections is not accepted as equivalent: every `QUERY_REJECTED` reason is a
member of `security/reasons.py`, `reject()` refuses anything else, and tests pin the wording.

## Running the server safely

- Use a dedicated database login with the least permission the job needs. Prefer a login that can
  read metadata only.
- Keep connection URLs and PII keys in the host's own configuration or environment. Never commit
  them or a `.env` file, and rotate a credential or key at once if it is exposed.
- Give every `all_pii_safe` alias its own key. Rotating a key or renaming an alias invalidates its
  existing tokens.
- Use a local, disposable, or explicitly non-production database for development and testing, never
  stored production credentials or data, and never commit raw database captures; see
  [CONTRIBUTING.md](../CONTRIBUTING.md).
