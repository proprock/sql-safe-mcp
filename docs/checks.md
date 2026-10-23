# Checks

## Commit/PR fast gate

On Linux and macOS, use GNU Make as the primary development interface. It requires GNU Make,
Bash, `uv`, and (for database targets) Docker Compose and OpenSSL:

```bash
make sync
make check
```

`make help` lists every available target. The direct commands remain useful for diagnosing a
specific failure:

```bash
uv sync --all-groups --locked
uv run ruff format --check .
uv run ruff check .
uv run ty check
uv run pytest tests/unit tests/contract -q
```

Install the existing commit hooks once after syncing dependencies, then run them before a commit:

```bash
make hooks-install
make hooks

# Direct equivalents
uv run prek install
uv run prek run --all-files
```

Never bypass a failing hook with `--no-verify`; fix the failure. Hooks do not replace the focused
test suite.

For a behavior-changing implementation phase, review statement and branch coverage separately:

```bash
make coverage

# Direct equivalent
uv run pytest tests/unit tests/contract --cov=sql_safe_mcp --cov-branch --cov-report=term-missing
```

Coverage does not replace behavioral assertions. Review the missing-line report, add relevant
tests or document an intentional exclusion, and report the result. Do not state that any check
passed unless it was executed.

GitHub Actions runs this commit/PR fast gate on supported Python versions, extended with
`tests/security -m "not deep"` (`HYPOTHESIS_PROFILE=security-fast`) and a coverage floor of 95%
(`--cov-fail-under=95`) over unit, contract and security tests. A separate job runs `pip-audit` on
the locked dependencies, so a known vulnerability fails the build. Dependabot proposes weekly
`uv` updates, grouping minor and patch versions.
`tests/security/sql_snapshot.json` pins the SQL generated for every allowlisted query on both
dialects; after an SQLGlot or generator change, review each changed statement, then regenerate it
with `UPDATE_SQL_SNAPSHOT=1 uv run pytest tests/security/test_sql_snapshot.py`.
CI also builds both distribution formats in a clean environment. Docker-backed SQL Server integration tests never run in hosted CI;
they remain an explicit local or externally managed disposable-database gate.

Validate the example configuration after defining its documented environment variables:

```bash
make config-check CONFIG=sql-safe-mcp.example-simple.yaml

# Direct equivalent
uv run sql-safe-mcp --config sql-safe-mcp.example-simple.yaml --check-config
```

## Milestone/release security gate

Per-task work runs the fast suite. A milestone is not closed, marked accepted in the roadmap, or
merged until the live suite also passes against the running SQL Server container with zero skips:

- every tool the milestone adds or changes has a live test through a real MCP client;
- every data path it changes (SQL generation, bind parameters, result types, reflection) is
  exercised with real SQL Server types and rows;
- rejected inputs are shown not to change a canary object;
- the run leaves no test logins or schemas behind.

Also run the live suite, or a focused `-k` subset, during a task that changes SQL generation,
execution, result encoding, reflection, or connection handling: fakes cannot prove those. Record
the date, image digest, ODBC driver, and test counts in the roadmap acceptance note. Passing is
never claimed from a skipped or partial run.

The normal Windows live gate starts or reuses the digest-pinned SQL Server 2022 container and keeps
it running between checks. Test SQL objects and credentials are uniquely named and cleaned after
each run:

```bash
make test-sqlserver

# Direct Linux/macOS script
./scripts/test-sqlserver
```

```powershell
# Windows equivalent
.\scripts\test-sqlserver.ps1
```

For an externally managed disposable SQL Server, define the admin URL directly:

```powershell
$env:SQL_SAFE_MCP_TEST_SQLSERVER_URL = "mssql+pyodbc://..."
uv run pytest tests/integration/sqlserver -m integration
```

MySQL and MariaDB have their own digest-pinned containers (`compose.mysql.yml`, project
`sql-safe-mcp-mysql`) and gate. It runs the same live checks against both engines with zero skips
and cleans its uniquely named databases and logins; changes to `MySqlExtras`, MySQL reflection, or
PyMySQL connection handling require it, and the milestone live gate requires it in addition to the
SQL Server run:

```bash
make test-mysql

# Direct Linux/macOS script
./scripts/test-mysql
```

```powershell
# Windows equivalent
.\scripts\test-mysql.ps1
```

`execute_sql` on MySQL and MariaDB is covered by the same script (`test_live_mysql_sql.py`):
tokenized projection, token predicates, injection payloads as binds, `%` and backslash literals
(also with `NO_BACKSLASH_ESCAPES` set server-wide), native result types, rejected-query canary,
and per-alias token isolation.

Externally managed servers use `SQL_SAFE_MCP_TEST_MYSQL_URL` and
`SQL_SAFE_MCP_TEST_MARIADB_URL` with `uv run pytest tests/integration/mysql -m integration`.
`make db-down-mysql`, `./scripts/test-mysql --reset`, or `.\scripts\test-mysql.ps1 -Reset`
removes the containers and volumes.

The release matrix starts (or reuses) all three containers, sets all three URLs, and runs every
live suite plus the cross-engine test (same public contract on the three engines, tokens of one
alias refused by the others with one identical `INVALID_PII_TOKEN`). It is part of the milestone
live gate and is never run by the single-engine scripts:

```bash
make test-matrix

# Direct Linux/macOS script
./scripts/test-matrix
```

```powershell
# Windows equivalent
.\scripts\test-matrix.ps1
```

Explicit local Docker cleanup is separate from the gate and removes test containers and volumes:

```bash
make db-down
make db-down-sqlserver
make db-down-mysql

# Direct Linux/macOS script
./scripts/test-sqlserver --reset
```

```powershell
# Windows equivalent
.\scripts\test-sqlserver.ps1 -Reset
```

`make db-up`, `make db-status`, and `make db-logs` manage or inspect the disposable containers
without running tests. `make demo-seed` fills the running SQL Server container with the synthetic
demo databases; use `DEMO_ARGS="--reset"` to recreate them.

The security suite is separate from the commit/PR fast gate. Run it for a milestone/release
security gate, and add it explicitly when running a subset:

```bash
make security

# Direct equivalent
uv run pytest tests/unit tests/contract tests/security -q
```

### Security gates (Milestone 2B)

The security gate includes the adversarial corpus (`tests/security/corpus/*.yaml`, every case must
fail with its expected code and never reach the database) and the Hypothesis properties under the
deterministic `security-fast` profile (about 200 examples per property).

Run before a milestone that changes `execute_sql` is closed:

```bash
make security
make security-deep

# Direct equivalents
uv run pytest tests/unit tests/contract tests/security -m "not deep"
uv run pytest tests/security -m deep
```

The deep run uses the randomized `security-deep` profile (3000 examples per property). A failure
prints an `@reproduce_failure` blob; pin a run with `--hypothesis-seed=N`. Move every minimized
counterexample into the corpus as a regression case.

Mutation testing runs on Linux or WSL only, in a clone on the Linux filesystem (not `/mnt/c`):

```bash
git clone <repo> ~/smm-mut && cd ~/smm-mut
make sync
make mutation
uv run mutmut results
uv run mutmut show <mutant>
```

Every survivor is either killed by a new test or recorded as equivalent in `security-model.md` with a
proof. Message wording is pinned through the fixed `Reason` catalog, so mutation of a message
string is not accepted as equivalent. An interrupted run is not evidence.

The writable-credential attack fixture (`tests/integration/sqlserver/test_live_attack.py`) runs as
part of the live gate and writes audit artifacts to `%TEMP%\sql-safe-mcp-audit`; attach them to the
review.
