# Deploying for health data of minors

How to configure sql-safe-mcp when an agent queries health records, especially records about
children. This document is technical input for a data protection impact assessment (DPIA) or a
HIPAA risk analysis. It is not legal advice: your counsel decides which rules apply and whether
these measures are enough.

Health data is a special category under GDPR art. 9, children get extra protection under GDPR
art. 8 and COPPA, and HIPAA requires minimum necessary access, audit controls, and protection in
transit. sql-safe-mcp cannot make a deployment compliant by itself; it narrows what an agent can
see and records what it asked for. It covers only part of 45 CFR 164.312: access control (a)
through access levels, audit controls (b) through `logging.audit`, and transmission security (e)(1)
through required TLS verification. It does not make a deployment HIPAA-compliant.

## What leaves the server is still PHI

Treat everything `execute_sql` returns as protected health information, for three reasons:

- **A token is an identifier, not a de-identified value.** A token is AES-GCM ciphertext of the
  original value under a key the server holds. 45 CFR 164.514(c) allows a re-identification code
  only if it is not derived from information about the individual. A token is derived from the
  value it protects, so count it as an identifier. Encryption with a secret key is a gray area;
  the conservative reading is the one used here.
- **Results are not de-identified.** Unprotected columns, counts, and dates still describe
  patients. Safe Harbor (164.514(b)(2)) needs every identifier below removed. Expert Determination
  (164.514(b)(1)) is the other route, and sql-safe-mcp does not perform it.
- **Everyone who sees a transcript is in scope.** A business associate agreement is needed with
  the model provider and with everyone who can read the transcript: the MCP host, log collectors,
  and support staff. Without a BAA, use a model that runs locally.

## Requirements and mechanisms

Sources: **[GDPR]** EU General Data Protection Regulation, **[HIPAA]** 45 CFR Parts 160 and 164,
**[COPPA]** 16 CFR Part 312, **[BP]** best practice without a direct rule.

| Requirement | Source | Mechanism |
|---|---|---|
| Direct identifiers (names, dates other than year, ZIP, phone, email, MRN, device and IP identifiers, photos) never leave the server in clear | [HIPAA §164.514(b)(2)] | A `pii.rules` entry for each such column, or `pii.mode: deny-by-default`. Check coverage with `sql-safe-mcp --verify-pii-rules --strict`. |
| Data protection by default: an unlisted column stays closed | [GDPR art. 25], [BP] | `pii.mode: deny-by-default` with an explicit `pii.exposed_columns` list. |
| Free text (notes, anamnesis, attachments) is unreachable; identifiers inside text cannot be tokenized | [BP] | `pii.deny`, plus column-level `DENY` for the database login. |
| Minimum necessary access | [HIPAA §164.502(b)], [GDPR art. 5(1)(c)] | A separate alias, database login, and key per purpose; `access_level: all_pii_safe` only where `execute_sql` is needed. Access levels are cumulative, so such an alias also reads stored procedure source (finding F-09); review procedure bodies for literal identifiers. |
| No linking of records across unrelated columns | [GDPR art. 5(1)(b)], [BP] | Token domains (`domain` on `pii.rules`), one per entity; token type checks; a fresh random nonce per token. |
| No partial disclosure (length, order, equality) | [GDPR art. 32], [BP] | Token padding to 32-byte buckets; a protected column is returned only as a token and compared only in `WHERE` by `=` or `IN` with tokens, never ordered or joined on; the position allowlist. Residual leaks remain: the length bucket, equality through token lookups, and the database's row order; see [security-model.md](security-model.md#trust-boundary). |
| Small counts are suppressed | [BP] (for example the CMS cell suppression policy, cells below 11) | `runtime.min_count_cell`. It does not stop differencing two overlapping queries; see [tools.md](tools.md). |
| Quasi-identifiers of minors (date of birth, ZIP, school, guardian names) | [HIPAA §164.514(b)(2)], [BP] | Protect them as PII. SQL functions are refused, so `YEAR(BirthDate)` is not available in a query. To publish a year or age group, add a computed column to the base table (SQL Server computed column, MySQL generated column) and list it in `exposed_columns` after review: the server cannot see that it derives from a protected date. `execute_sql` reads base tables only, not views. |
| Access log: who, when, which tables and columns, how many rows | [HIPAA §164.312(b)], [GDPR art. 30] | `logging.audit: true`; the line holds names and counts, never SQL text, values, or tokens. The line carries no timestamp or user: the time comes from the host's log collector, and identity needs one alias per user or agent. |
| Encryption in transit | [HIPAA §164.312(e)(1)], [GDPR art. 32] | `require_tls` (on by default) requires an encrypted connection with a verified certificate. |
| Key held apart from data; limited life of pseudonyms | [GDPR art. 4(5), art. 32], [BP] | `pii_key_file` with mode `0600`, `0640` or `0440`; a new key on restart invalidates every token; `runtime.token_ttl_seconds`. |
| Minors' rows unreachable from general-purpose aliases | [GDPR art. 8], [BP] | Not in sql-safe-mcp. Use row-level security in the database and a separate login. `execute_sql` cannot select a view, so a view is not an isolation boundary for it. |
| Data kept no longer than needed | [COPPA §312.10], [GDPR art. 5(1)(e)] | `runtime.token_ttl_seconds` makes tokens in an old transcript stop working on the server. Transcripts also hold unprotected values, counts, and dates, which are PHI and follow the organization's retention policy. |
| Prompt injection carried in database rows | [BP] | Outside the server's control. The host must treat results as data, never as instructions. |
| Evidence before release | [HIPAA §164.308(a)(8)], [BP] | The security suite, mutation testing, and live attack tests described in [security-model.md](security-model.md). |

## Safe Harbor identifiers (45 CFR 164.514(b)(2))

Safe Harbor removes all of these identifiers of the individual, or of relatives, employers, or
household members, and the covered entity has no actual knowledge that the remaining information
could identify the person (164.514(b)(2)(ii)):

- (A) Names.
- (B) Geographic subdivisions smaller than a state: street address, city, county, precinct, ZIP
  code, and equivalent geocodes. The first three ZIP digits may remain only if all ZIP codes with
  those digits together cover more than 20,000 people according to the current Census data;
  otherwise they are replaced with 000.
- (C) All elements of dates (except year) directly related to an individual, including birth
  date, admission date, discharge date, and date of death. All ages over 89, and all elements of
  dates (including year) that indicate such an age, unless aggregated into a single category of
  age 90 or older.
- (D) Telephone numbers.
- (E) Fax numbers.
- (F) Email addresses.
- (G) Social security numbers.
- (H) Medical record numbers.
- (I) Health plan beneficiary numbers.
- (J) Account numbers.
- (K) Certificate or license numbers.
- (L) Vehicle identifiers and serial numbers, including license plate numbers.
- (M) Device identifiers and serial numbers.
- (N) Web universal resource locators (URLs).
- (O) Internet protocol (IP) address numbers.
- (P) Biometric identifiers, including finger and voice prints.
- (Q) Full-face photographs and any comparable images.
- (R) Any other unique identifying number, characteristic, or code, except a re-identification
  code that meets 164.514(c).

Two points often missed:

- **Primary keys.** A key such as `PatientId` identifies a person. The exception in (R) covers a
  re-identification code under 164.514(c). Such a code must not be derived from information about
  the individual (c)(1), and must not be used or disclosed for any other purpose (c)(2). A
  `PatientId` that the whole system uses is used for other purposes, so the exception does not
  apply, and in clear it falls under (R). Protect it as PII, as the example protects `MRN`.
- **Dates more specific than a year.** Any date tied to an individual is under (C). A year is not
  listed, but it remains identifying in combination with the other items.

## Operator checklist

- [ ] A dedicated alias, database login, and key for the health database. The login reads only
      what the job needs and carries column-level `DENY` on free-text columns.
- [ ] `access_level: all_pii_safe` only where `execute_sql` is needed. Such an alias also reads
      stored procedure source (finding F-09), so review procedure bodies for literal identifiers.
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
- [ ] Transcripts are kept under the organization's PHI retention policy, and the MCP host treats
      query results as untrusted data.

## Outside the server

The server does not do the following and cannot. The operator must provide them.

**Contracts and data flow**

- Business associate agreements with the model provider and with everyone who sees a transcript:
  the MCP host, log collectors, and support.
- Provider settings: no training on the data, an agreed retention period, and a region.
- An agent with access to PHI should not have outbound tools in the same session (web, email,
  other MCP servers). A prompt injection in a table row could otherwise send data out.

**Database**

- A read-only login for each purpose. Column-level `DENY` on free text, attachments, and columns
  the agent does not need. This is protection against any error in the server.
- An `all_pii_safe` alias reads stored procedure source (finding F-09). Review procedure bodies
  for literal identifiers before granting it. A database permission that blocks this has not been
  verified against this server, so this document does not recommend one.
- A read replica, or resource limits (SQL Server Resource Governor, MySQL `MAX_USER_CONNECTIONS`),
  so that an agent's heavy query does not slow the clinical system.
- Database audit (SQL Server Audit, the MariaDB audit plugin) with query text. Only that answers
  "who read patient X's record".
- Generalized values as computed columns on the base tables, because the server does not read
  views (see the table above).
- Encryption at rest (TDE), backups, and TLS 1.2 or later with a verifiable certificate.

**Host**

- The server runs under a dedicated account, and only that account reads the key file. On Windows,
  permissions are set by hand with ACLs; the server does not check them.
- Disk encryption. Transcripts and the MCP log are stored on the host's disk.
- Transcripts are kept under the organization's PHI retention policy, with scheduled deletion.
  `runtime.token_ttl_seconds` only makes tokens in an old transcript stop working on the server;
  unprotected values, counts, and dates in a transcript do not expire with it.
- Server stderr is collected into tamper-evident storage, kept for the period the organization's
  retention policy sets. Many organizations use six years by analogy with 164.316(b)(2)(i), which
  covers policy and procedure documentation, not logs. Clock synchronization (NTP) is required.
- The PII key is rotated on a schedule, with a restart. The key is not included in configuration
  backups.

**Organization**

- A risk analysis and a DPIA for the specific deployment. This document is an input to them.
- Regular review of the access log, an incident procedure, and staff training.
- Expert Determination, if the organization intends to treat query results as de-identified.
- Related laws that HIPAA does not cover: 42 CFR Part 2 (substance use treatment), state laws on
  minors' data, and GDPR.
- Do not describe the deployment as "HIPAA compliant". Acceptable: "covers only part of 45 CFR
  164.312: access control (a) through access levels, audit controls (b) through `logging.audit`,
  and transmission security (e)(1) through required TLS verification."

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
