"""Integration tests against the demo database from sql/setup.sql.

Skipped unless SQLGUARD_DB_PASSWORD is set (directly or via .env).
"""

import pymysql
import pytest

from sql_guard import GuardResult, Policy
from sql_guard.cli import _load_dotenv
from sql_guard.db import ConnectionSettings, execute_guarded, run

_load_dotenv()
SETTINGS = ConnectionSettings.from_env()
pytestmark = pytest.mark.skipif(not SETTINGS.password, reason="SQLGUARD_DB_PASSWORD not set")

POLICY = Policy.from_file("policy.json")


def test_allowed_query_is_capped():
    result, rows = run("SELECT * FROM orders", POLICY, SETTINGS)
    assert result.allowed and result.sql.endswith("LIMIT 100")
    assert len(rows.rows) == 100
    assert rows.columns[:2] == ["id", "customer_id"]


def test_join_and_aggregate():
    sql = ("SELECT c.country, COUNT(*) AS n FROM orders o "
           "JOIN customers c ON c.id = o.customer_id GROUP BY c.country ORDER BY n DESC")
    _, rows = run(sql, POLICY, SETTINGS)
    assert sum(r[1] for r in rows.rows) == 300


def test_blocked_query_never_reaches_db():
    result, rows = run("SELECT * FROM secrets", POLICY, SETTINGS)
    assert not result.allowed and rows is None


def test_refuses_unapproved_result():
    with pytest.raises(ValueError):
        execute_guarded(GuardResult(allowed=False, sql="SELECT 1", reasons=()), SETTINGS)


# --- layer 2: pretend the guard was bypassed --------------------------------

def _forged(sql):
    return GuardResult(allowed=True, sql=sql, reasons=(), row_cap=10)


@pytest.mark.parametrize("sql", [
    "DELETE FROM orders",
    "UPDATE customers SET name = 'pwned'",
    "INSERT INTO products (name, price) VALUES ('x', 1)",
    "DROP TABLE orders",
])
def test_db_rejects_writes_even_if_guard_bypassed(sql):
    with pytest.raises(pymysql.err.MySQLError):
        execute_guarded(_forged(sql), SETTINGS)


def test_db_rejects_unlisted_table_even_if_guard_bypassed():
    with pytest.raises(pymysql.err.MySQLError) as e:
        execute_guarded(_forged("SELECT * FROM secrets"), SETTINGS)
    assert e.value.args[0] == 1142   # SELECT command denied


def test_db_rejects_stacked_statements_even_if_guard_bypassed():
    with pytest.raises(pymysql.err.MySQLError):
        execute_guarded(_forged("SELECT 1; DELETE FROM orders"), SETTINGS)


def test_data_unchanged():
    _, rows = run("SELECT COUNT(*) FROM orders", POLICY, SETTINGS)
    assert rows.rows == [[300]]
