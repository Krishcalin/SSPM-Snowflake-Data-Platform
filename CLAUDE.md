# CLAUDE.md — Snowflake SSPM Scanner

## Project overview

This is a Python-based **SaaS Security Posture Management (SSPM)** scanner for **Snowflake Data Platform**. It connects to a live Snowflake account via the Snowflake Python Connector, runs SQL-based audit queries aligned with the **CIS Snowflake Foundations Benchmark v1.0.0**, and generates scored reports.

- **Version**: 1.0.0
- **License**: MIT
- **Python**: 3.10+
- **Dependencies**: `snowflake-connector-python>=3.6.0`, `cryptography>=41.0.0`
- **Architecture**: Single-file scanner (`snowflake_scanner.py`)

## Repository layout

```
snowflake_scanner.py    Single-file scanner (all logic in one file)
requirements.txt        Python dependencies
.env.example            Environment variable template
.gitignore              Python + secrets exclusions
README.md               Full documentation, check table, usage
banner.svg              Project branding banner
LICENSE                 MIT license
CLAUDE.md               This file — development guide
```

## Build and run

```bash
# Install dependencies
pip install -r requirements.txt

# Run with password auth
python snowflake_scanner.py \
    --account xy12345.us-east-1 \
    --user admin_user \
    --password "$SNOWFLAKE_PASSWORD" \
    --role ACCOUNTADMIN \
    --json report.json --html report.html

# Run with key pair auth
python snowflake_scanner.py \
    --account xy12345 --user admin_user \
    --private-key-path rsa_key.p8 --role ACCOUNTADMIN

# Run with SSO
python snowflake_scanner.py \
    --account xy12345 --user admin_user \
    --authenticator externalbrowser

# Env var fallback (all CLI flags have env var equivalents)
export SNOWFLAKE_ACCOUNT=xy12345.us-east-1
export SNOWFLAKE_USER=admin_user
export SNOWFLAKE_PASSWORD=secret
python snowflake_scanner.py --json report.json
```

## Scanner architecture

### Single-file design

This scanner follows the same single-file pattern as the SSPM-O365, SSPM-Oracle-SaaS-Cloud, and SSPM-ServiceNow scanners. All logic resides in `snowflake_scanner.py` for zero-config deployment.

### Internal structure

```
snowflake_scanner.py
  |
  +-- COMPLIANCE_MAP          Dict mapping rule_id -> {cis, nist, iso, soc2}
  +-- Finding                 Data model (rule_id, title, status, severity, ...)
  +-- SnowflakeClient         Snowflake connector wrapper
  |   +-- connect()           Authenticate (password / key pair / SSO)
  |   +-- query(sql)          Execute SQL, return list[dict]
  |   +-- query_scalar(sql)   Execute SQL, return first value
  +-- SnowflakeScanner        39 CIS check methods
  |   +-- check_1_1..1_17()   Section 1: Identity & Access Management
  |   +-- check_2_1..2_9()    Section 2: Monitoring & Alerting
  |   +-- check_3_1..3_2()    Section 3: Networking
  |   +-- check_4_1..4_11()   Section 4: Data Protection
  |   +-- run_all()           Execute all checks sequentially
  +-- compute_score()         Severity-weighted scoring (0-100)
  +-- print_console_report()  ANSI colour console output
  +-- write_json_report()     JSON file export
  +-- write_html_report()     Self-contained HTML dashboard
  +-- build_parser()          argparse CLI definition
  +-- main()                  Entry point
```

### 3-phase pipeline

1. **Connect** (`SnowflakeClient`): Authenticate via password, key pair, or externalbrowser SSO
2. **Scan** (`SnowflakeScanner`): Run 39 check methods, each executing SQL against `SNOWFLAKE.ACCOUNT_USAGE` views and `SHOW` commands, producing `Finding` objects
3. **Score & Report**: Compute severity-weighted posture score, emit console/JSON/HTML output

## Check ID format

| Prefix | Domain | CIS Section | Count |
|--------|--------|-------------|-------|
| `SF-IAM-NNN` | Identity & Access Management | 1.1 - 1.17 | 17 |
| `SF-MON-NNN` | Monitoring & Alerting | 2.1 - 2.9 | 9 |
| `SF-NET-NNN` | Networking | 3.1 - 3.2 | 2 |
| `SF-DP-NNN`  | Data Protection | 4.1 - 4.11 | 11 |

## Adding a new check

1. Add a method `check_X_Y_description(self)` to `SnowflakeScanner`
2. Inside the method: run SQL via `self.client.query()`, evaluate result, call `self._add(Finding(...))`
3. Add the method to the `checks` list in `run_all()`
4. Add a `COMPLIANCE_MAP` entry for the new rule ID
5. Update the README check table

## Severity weights

| Severity | Weight | Use when |
|----------|--------|----------|
| CRITICAL | 25 | Account takeover risk, MFA not enforced |
| HIGH | 15 | Significant security gap (no SSO, no network policy) |
| MEDIUM | 8 | Configuration weakness (no rekeying, missing email) |
| LOW | 3 | Best practice improvement (driver version monitoring) |
| INFO | 0 | Informational only |

## Status values

- `PASS` — control satisfied (full weight earned)
- `FAIL` — control violated (0 weight)
- `WARN` — partial compliance or manual verification needed (50% weight)
- `SKIP` — not evaluable, e.g. missing tags (excluded from score)
- `ERROR` — check execution failed (excluded from score)

## Compliance mapping

Each finding maps to four frameworks:

| Key | Framework |
|-----|-----------|
| `cis_snowflake` | CIS Snowflake Foundations Benchmark v1.0.0 |
| `nist_800_53` | NIST SP 800-53 Rev 5 |
| `iso_27001` | ISO/IEC 27001:2022 |
| `soc2` | SOC 2 Type II Trust Services Criteria |

## SQL query patterns

The scanner uses two query patterns:

### Pattern 1: SHOW + RESULT_SCAN
```sql
SHOW SECURITY INTEGRATIONS;
SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
WHERE "type" LIKE 'SAML2' AND "enabled" = 'true';
```

### Pattern 2: Direct ACCOUNT_USAGE queries
```sql
SELECT NAME, DEFAULT_ROLE
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE DEFAULT_ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN')
  AND DELETED_ON IS NULL AND DISABLED = 'false';
```

Note: ACCOUNT_USAGE views have up to 2 hours of data latency. SHOW commands return real-time data but require specific privileges.

## Required Snowflake permissions

| Permission | Purpose |
|-----------|---------|
| `SECURITY_VIEWER` on SNOWFLAKE DB | Users, grants, login history, password policies |
| `GOVERNANCE_VIEWER` on SNOWFLAKE DB | Policy references, tag references, session policies |
| `USAGE` on security integrations | Verify SSO/SCIM/OAuth integrations |
| `OWNERSHIP` on network policies | Inspect network policy ALLOWED_IP_LIST |

Using `ACCOUNTADMIN` role covers all of the above.

## Important notes

- The scanner is **read-only** — it never modifies the Snowflake account
- Credentials must never be committed; use `.env` (gitignored) or CI/CD secrets
- The HTML report uses a Snowflake-branded dark theme with embedded CSS (no external dependencies)
- Exit code 1 if any CRITICAL finding fails **or** score is below `--min-score`
- Service account checks (1.6, 3.2) require users tagged with `ACCOUNT_TYPE='service'`; they degrade to SKIP if the tag doesn't exist
- Tri-Secret Secure (4.9) cannot be verified via SQL; always returns WARN
- Monitoring checks (2.x) verify that audit *data exists*, not that alerting tasks are configured
- Some features require Snowflake Enterprise Edition or higher: periodic rekeying (4.1), data retention > 1 day (4.3/4.4), masking policies (4.10), row access policies (4.11)
- Column names from `SHOW` commands use lowercase quoted identifiers (`"value"`); from `ACCOUNT_USAGE` views use uppercase (`VALUE`)
