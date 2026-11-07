# Deploying for health data of minors

How to configure sql-safe-mcp when an agent queries health records, especially records about
children. This document is technical input for a data protection impact assessment (DPIA) or a
HIPAA risk analysis. It is not legal advice: your counsel decides which rules apply and whether
these measures are enough.

Health data is a special category under GDPR art. 9, children get extra protection under GDPR
art. 8 and COPPA, and HIPAA requires minimum necessary access, audit controls, and protection in
transit. sql-safe-mcp cannot make a deployment compliant by itself; it narrows what an agent can
see and records what it asked for.

## Requirements and mechanisms

Sources: **[GDPR]** EU General Data Protection Regulation, **[HIPAA]** 45 CFR Parts 160 and 164,
**[COPPA]** 16 CFR Part 312, **[BP]** best practice without a direct rule.

| Requirement | Source | Mechanism |
|---|---|---|
| Direct identifiers (names, dates other than year, ZIP, phone, email, MRN, device and IP identifiers, photos) never leave the server in clear | [HIPAA §164.514(b)(2)] | A `pii.rules` entry for each such column, or `pii.mode: deny-by-default`. Check coverage with `sql-safe-mcp --verify-pii-rules --strict`. |
| Data protection by default: an unlisted column stays closed | [GDPR art. 25], [BP] | `pii.mode: deny-by-default` with an explicit `pii.exposed_columns` list. |
| Free text (notes, anamnesis, attachments) is unreachable; identifiers inside text cannot be tokenized | [BP] | `pii.deny`, plus column-level `DENY` for the database login. |
| Minimum necessary access | [HIPAA §164.502(b)], [GDPR art. 5(1)(c)] | A separate alias, database login, and key per purpose; `access_level: all_pii_safe` only where `execute_sql` is needed. Access levels are cumulative, so such an alias also returns stored procedure definitions; deny the login permission to read definitions (`VIEW DEFINITION`) if they may contain identifiers. |
| No linking of records across unrelated columns | [GDPR art. 5(1)(b)], [BP] | Token domains (`domain` on `pii.rules`), one per entity; token type checks; a fresh random nonce per token. |
| No partial disclosure (length, order, equality) | [GDPR art. 32], [BP] | Token padding to 32-byte buckets; a protected column is returned only as a token and compared only in `WHERE` by `=` or `IN` with tokens, never ordered or joined on; the position allowlist. Residual leaks remain: the length bucket, equality through token lookups, and the database's row order; see [security-model.md](security-model.md#trust-boundary). |
| Small counts are suppressed | [BP] (for example the CMS cell suppression policy, cells below 11) | `runtime.min_count_cell`. It does not stop differencing two overlapping queries; see [tools.md](tools.md). |
| Quasi-identifiers of minors (date of birth, ZIP, school, guardian names) | [HIPAA §164.514(b)(2)], [BP] | Protect them as PII. SQL functions are refused, so `YEAR(BirthDate)` is not available; publish an age group or year through a database view only if that is acceptable. |
| Access log: who, when, which tables and columns, how many rows | [HIPAA §164.312(b)], [GDPR art. 30] | `logging.audit: true`; the line holds names and counts, never SQL text, values, or tokens. The line carries no timestamp or user: the time comes from the host's log collector, and identity needs one alias per user or agent. |
| Encryption in transit | [HIPAA §164.312(e)(1)], [GDPR art. 32] | `require_tls` (on by default) requires an encrypted connection with a verified certificate. |
| Key held apart from data; limited life of pseudonyms | [GDPR art. 4(5), art. 32], [BP] | `pii_key_file` with mode `0600`, `0640` or `0440`; a new key on restart invalidates every token; `runtime.token_ttl_seconds`. |
| Minors' rows unreachable from general-purpose aliases | [GDPR art. 8], [BP] | Not in sql-safe-mcp. Use a database view or row-level security and a separate login. |
| Tokens are not kept longer than needed | [COPPA §312.10], [GDPR art. 5(1)(e)] | `runtime.token_ttl_seconds`; the host must not keep transcripts with tokens beyond that period. |
| Prompt injection carried in database rows | [BP] | Outside the server's control. The host must treat results as data, never as instructions. |
| Evidence before release | [HIPAA §164.308(a)(8)], [BP] | The security suite, mutation testing, and live attack tests described in [security-model.md](security-model.md). |

## Operator checklist

- [ ] A dedicated alias, database login, and key for the health database. The login reads only
      what the job needs and carries column-level `DENY` on free-text columns.
- [ ] `access_level: all_pii_safe`. It also serves stored procedure definitions, so the login
      must not be able to read definitions that contain literal identifiers.
- [ ] `pii.mode: deny-by-default`, with `exposed_columns` limited to non-identifying columns.
- [ ] `pii.deny` for free text, attachments, and photos.
- [ ] `pii.rules` with one `domain` per entity (patient, guardian, clinical).
- [ ] Dates of birth, ZIP codes, schools, and guardian names protected like names.
- [ ] `sql-safe-mcp --verify-pii-rules --strict` passes, and its "looks personal" warnings are
      reviewed.
- [ ] `require_tls` left on, with a verified certificate.
- [ ] `pii_key_file` on a secret mount, readable by the server user only.
- [ ] `runtime.token_ttl_seconds` set; the key changed between work periods with a restart.
- [ ] `runtime.min_count_cell` set (for example `11`).
- [ ] `logging.audit: true`, with stderr collected and retained per policy.
- [ ] The MCP host does not store transcripts containing tokens longer than the token lifetime and
      treats query results as untrusted data.

## Example configuration

```yaml
version: 1
servers:
  peds_ro:
    engine: sqlserver
    access_level: all_pii_safe
    connection_url: "${PEDS_SQL_URL}" # login with column-level DENY on Notes and Attachment
    pii_key_file: /run/secrets/peds_pii_key
    pii:
      mode: deny-by-default
      exposed_columns:
        - {table: Visits, columns: [VisitId, DepartmentCode, VisitYear]}
      deny:
        - {table: "*", columns: [Notes, Anamnesis, Attachment]}
      rules:
        - {database: "*", table: Patients, columns: [MRN], domain: patient}
        - {database: "*", table: Patients, columns: [FirstName, LastName, BirthDate, Zip], domain: patient}
        - {database: "*", table: Guardians, columns: [GuardianName, GuardianPhone], domain: guardian}
        - {database: "*", table: Diagnoses, columns: [IcdCode, Description], domain: clinical}
runtime:
  hard_max_rows: 200
  min_count_cell: 11
  token_ttl_seconds: 86400
logging:
  level: INFO
  audit: true
```

`PEDS_SQL_URL` must include `Encrypt=yes` and must not set `TrustServerCertificate=yes`; see
[configuration.md](configuration.md#verified-tls).
