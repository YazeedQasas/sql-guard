# sql-guard

A guard layer for AI-generated SQL. It either **blocks** a query with machine-readable reasons, or **returns a safe, row-capped SELECT** to run on a read-only MySQL connection.

```text
LLM ──SQL──▶ guard() ──blocked──▶ { allowed: false, reasons: [...] }
                │
                └─allowed─▶ capped SELECT ──▶ read-only MySQL user
                                              (SELECT grants only, READ ONLY txn,
                                               max_execution_time, rollback)
```

## Rules

| Rule | How it is enforced | Reason code |
|---|---|---|
| No comments | Scanner finds `--`, `#`, `/* */` and MySQL's *executable* `/*! */` outside literals | `COMMENT_NOT_ALLOWED` |
| Single statement | Any `;` except one trailing one; also checks the parser's statement count | `MULTIPLE_STATEMENTS` |
| Keyword denylist | Bare words outside strings/backtick identifiers: DML, DDL, `GRANT`, `CALL`, `SET`, `LOCK`, `INTO`/`OUTFILE`, `SLEEP`, `BENCHMARK`, `LOAD_FILE`… | `DENIED_KEYWORD` |
| SELECT only | AST root must be `SELECT` / `UNION` / `INTERSECT` / `EXCEPT` (CTEs included); no write or locking nodes anywhere in the tree | `NOT_SELECT` |
| Table allowlist | Every table in joins, subqueries, UNIONs and CTE bodies; CTE names are exempt **only within their own scope**; `mysql`, `information_schema`, `performance_schema`, `sys` are always blocked | `TABLE_NOT_ALLOWED` |
| Forced row cap | Adds `LIMIT max_rows`, lowers a larger one, replaces a non-numeric one (`?`, expressions), keeps `OFFSET` | — (see `row_cap`) |
| No variables | `@x`, `@@version`, `@x := …` | `VARIABLE_NOT_ALLOWED` |

Other codes: `EMPTY_QUERY`, `LEX_ERROR` (unterminated string/comment), `PARSE_ERROR`.

All checks run, so a blocked result lists **every** problem, not just the first.

> **TOP vs LIMIT:** MySQL has no `TOP`, so the cap is enforced as a forced `LIMIT`.

## Quickstart

### 1. Install

```powershell
python -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
```

### 2. Create the demo database (MySQL Workbench)

1. Open `sql/setup.sql` in Workbench (**File → Open SQL Script**).
2. Replace `change-me-ro-password` with a password of your own.
3. Run it as root (lightning-bolt icon). The last result grid should show three `GRANT SELECT` lines.
4. Copy `.env.example` to `.env` and set `SQLGUARD_DB_PASSWORD` to the same password.

This creates `sqlguard_demo` with `customers`, `products`, 300 `orders`, and a `secrets` table that is **not** on the allowlist and **not** granted to `sqlguard_ro`.

### 3. Use it

```powershell
# check only
.venv\Scripts\sql-guard check "SELECT * FROM orders"

# check and run on the read-only connection
.venv\Scripts\sql-guard check "SELECT country, COUNT(*) FROM customers GROUP BY country" --execute

# from stdin
Get-Content query.sql | .venv\Scripts\sql-guard check -
```

Exit codes: `0` allowed, `2` blocked, `1` error.

### Python API

```python
from sql_guard import Policy, guard
from sql_guard.db import ConnectionSettings, run

policy = Policy(allowed_tables={"customers", "orders"}, max_rows=100, default_database="sqlguard_demo")

result = guard(llm_sql, policy)
if result.allowed:
    print(result.sql)            # safe, capped SELECT
else:
    for r in result.reasons:     # feed these back to the LLM to retry
        print(r.code, r.detail)

# or guard + execute in one step
result, rows = run(llm_sql, policy, ConnectionSettings.from_env())
```

## Output

Allowed:

```json
{
  "allowed": true,
  "sql": "SELECT * FROM orders LIMIT 100",
  "reasons": [],
  "row_cap": 100,
  "tables": ["orders"]
}
```

Blocked:

```json
{
  "allowed": false,
  "sql": null,
  "reasons": [
    {"code": "MULTIPLE_STATEMENTS", "message": "only a single statement is allowed", "detail": {"positions": [23]}},
    {"code": "DENIED_KEYWORD", "message": "keyword DROP is not allowed", "detail": {"keyword": "DROP", "position": 25}}
  ],
  "row_cap": null,
  "tables": []
}
```

## Policy file

`policy.json`:

```json
{
  "allowed_tables": ["customers", "orders", "products"],
  "default_database": "sqlguard_demo",
  "max_rows": 100,
  "extra_denied_keywords": [],
  "allow_keywords": []
}
```

- `allowed_tables`: plain names match the default database; use `db.table` for others.
- `extra_denied_keywords` / `allow_keywords`: add to or remove from the default denylist.

## Tests

```powershell
.venv\Scripts\python -m pytest
```

`tests/test_mysql.py` runs against the demo DB when `SQLGUARD_DB_PASSWORD` is set. Among other things, it hands the executor *forged* "allowed" results (`DELETE`, `DROP`, `SELECT * FROM secrets`, stacked statements) to prove the database layer rejects them on its own.

## Threat model and limits

- **The guard is not the only defence.** Always run its output as a user with SELECT-only grants on the allowlisted tables. `sql/setup.sql` shows how.
- **Deliberately strict.** `--` is banned even where MySQL would read it as arithmetic (`5--3`). Denylisted words are banned even as unquoted column names (``use `start` `` instead, or `allow_keywords`).
- **The output SQL is regenerated** by sqlglot (MySQL dialect), not string-patched. It is equivalent to the input but may be formatted differently (`AS` added to aliases, `LIMIT a, b` becomes `LIMIT b OFFSET a`).
- **Column-level access is not checked.** Use views or column grants if some columns are sensitive.
- **Cost is not checked.** A cartesian join under the row cap can still be slow; `max_execution_time` (default 5 s) is the backstop.
- Assumes MySQL's default `sql_mode`: `"..."` is a string, not an identifier (`ANSI_QUOTES` off).
