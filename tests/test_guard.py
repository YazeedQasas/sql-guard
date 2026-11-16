import json

import pytest

from sql_guard import Code, Policy, guard

POLICY = Policy(
    allowed_tables={"customers", "orders", "products"},
    max_rows=100,
    default_database="sqlguard_demo",
)


def codes(sql, policy=POLICY):
    return [r.code for r in guard(sql, policy).reasons]


def ok(sql, policy=POLICY):
    r = guard(sql, policy)
    assert r.allowed, [(x.code, x.detail) for x in r.reasons]
    return r


# --- allowed queries ---------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT * FROM customers",
    "select id, name from customers where id = 1",
    "SELECT * FROM `customers`",
    "SELECT * FROM CUSTOMERS",
    "SELECT * FROM sqlguard_demo.customers",
    "SELECT c.name, COUNT(*) FROM customers c JOIN orders o ON o.customer_id = c.id GROUP BY c.name",
    "SELECT id FROM customers UNION SELECT customer_id FROM orders",
    "WITH big AS (SELECT * FROM orders WHERE total > 100) SELECT * FROM big",
    "SELECT * FROM (SELECT * FROM products) p",
    "SELECT * FROM customers WHERE id IN (SELECT customer_id FROM orders)",
    "SELECT REPLACE(name, 'a', 'b') FROM customers",
    "SELECT 1",
    "SELECT 1;",
    "SELECT `delete`, `update` FROM customers",
])
def test_allowed(sql):
    ok(sql)


def test_strings_that_look_like_attacks_are_data():
    r = ok("SELECT * FROM customers WHERE name = 'x''; DROP TABLE customers; -- #/*'")
    assert "DROP TABLE customers" in r.sql


def test_backslash_escaped_quote_does_not_end_string():
    ok(r"SELECT * FROM customers WHERE name = 'it\'s; DELETE FROM x'")


# --- row cap -----------------------------------------------------------------

@pytest.mark.parametrize("sql,expected_cap,expected_tail", [
    ("SELECT * FROM customers", 100, "LIMIT 100"),
    ("SELECT * FROM customers LIMIT 5", 5, "LIMIT 5"),
    ("SELECT * FROM customers LIMIT 0", 0, "LIMIT 0"),
    ("SELECT * FROM customers LIMIT 100", 100, "LIMIT 100"),
    ("SELECT * FROM customers LIMIT 5000", 100, "LIMIT 100"),
    ("SELECT * FROM customers LIMIT ?", 100, "LIMIT 100"),
    ("SELECT * FROM customers LIMIT 10, 5000", 100, "LIMIT 100 OFFSET 10"),
    ("SELECT * FROM customers LIMIT 5000 OFFSET 20", 100, "LIMIT 100 OFFSET 20"),
    ("SELECT id FROM customers UNION SELECT id FROM orders", 100, "LIMIT 100"),
    ("(SELECT id FROM customers) UNION (SELECT id FROM orders LIMIT 3) LIMIT 9999", 100, "LIMIT 100"),
])
def test_row_cap(sql, expected_cap, expected_tail):
    r = ok(sql)
    assert r.row_cap == expected_cap
    assert r.sql.endswith(expected_tail)


def test_cap_follows_policy():
    r = ok("SELECT * FROM customers", Policy(allowed_tables={"customers"}, max_rows=7))
    assert r.sql.endswith("LIMIT 7")


# --- comments ----------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT * FROM customers -- hi",
    "SELECT * FROM customers --",
    "SELECT * FROM customers # hi",
    "SELECT * FROM customers /* hi */",
    "SELECT * FROM customers /*!50000 UNION SELECT * FROM secrets */",
    "SELECT/**/1",
    "SELECT 5--3",
])
def test_comments_blocked(sql):
    assert Code.COMMENT_NOT_ALLOWED in codes(sql)


# --- single statement --------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT 1; SELECT 2",
    "SELECT * FROM customers; DROP TABLE customers",
    "SELECT 1;;",
    "; SELECT 1",
])
def test_multiple_statements_blocked(sql):
    assert Code.MULTIPLE_STATEMENTS in codes(sql)


# --- SELECT only -------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "DELETE FROM customers",
    "UPDATE customers SET name = 'x'",
    "INSERT INTO customers (name) VALUES ('x')",
    "REPLACE INTO customers (id) VALUES (1)",
    "DROP TABLE customers",
    "SHOW TABLES",
    "DESCRIBE customers",
    "EXPLAIN SELECT * FROM customers",
])
def test_non_select_blocked(sql):
    r = guard(sql, POLICY)
    assert not r.allowed
    assert {Code.NOT_SELECT, Code.DENIED_KEYWORD, Code.PARSE_ERROR} & {x.code for x in r.reasons}


@pytest.mark.parametrize("sql", [
    "SELECT * FROM customers FOR UPDATE",
    "SELECT * FROM customers FOR SHARE",
    "SELECT * FROM customers LOCK IN SHARE MODE",
])
def test_locking_reads_blocked(sql):
    assert not guard(sql, POLICY).allowed


# --- keyword denylist --------------------------------------------------------

@pytest.mark.parametrize("sql,keyword", [
    ("SELECT SLEEP(5)", "SLEEP"),
    ("SELECT BENCHMARK(1000000, MD5('a'))", "BENCHMARK"),
    ("SELECT LOAD_FILE('/etc/passwd')", "LOAD_FILE"),
    ("SELECT * FROM customers INTO OUTFILE '/tmp/x'", "INTO"),
    ("SELECT * INTO DUMPFILE '/tmp/x' FROM customers", "INTO"),
    ("SELECT GET_LOCK('x', 10)", "GET_LOCK"),
])
def test_denied_keywords(sql, keyword):
    r = guard(sql, POLICY)
    assert not r.allowed
    assert keyword in [x.detail.get("keyword") for x in r.reasons]


def test_extra_denied_keywords_from_policy():
    p = Policy.from_dict({"allowed_tables": ["customers"], "extra_denied_keywords": ["md5"]})
    assert Code.DENIED_KEYWORD in codes("SELECT MD5(name) FROM customers", p)


def test_keyword_inside_identifier_or_literal_is_fine():
    ok("SELECT `drop` FROM customers WHERE name = 'DELETE'")


# --- variables ---------------------------------------------------------------

@pytest.mark.parametrize("sql", [
    "SELECT @@version",
    "SELECT @x := 1",
    "SELECT * FROM customers WHERE id = @id",
])
def test_variables_blocked(sql):
    assert Code.VARIABLE_NOT_ALLOWED in codes(sql)


# --- table allowlist ---------------------------------------------------------

@pytest.mark.parametrize("sql,table", [
    ("SELECT * FROM secrets", "secrets"),
    ("SELECT id FROM customers UNION SELECT id FROM secrets", "secrets"),
    ("SELECT * FROM customers c JOIN secrets s ON s.id = c.id", "secrets"),
    ("SELECT * FROM (SELECT * FROM secrets) x", "secrets"),
    ("SELECT * FROM customers WHERE id IN (SELECT id FROM secrets)", "secrets"),
    ("SELECT (SELECT MAX(id) FROM secrets) FROM customers", "secrets"),
    ("WITH c AS (SELECT * FROM secrets) SELECT * FROM c", "secrets"),
    ("SELECT * FROM mysql.user", "mysql.user"),
    ("SELECT * FROM information_schema.tables", "information_schema.tables"),
    ("SELECT * FROM other_db.customers", "other_db.customers"),
])
def test_table_not_allowed(sql, table):
    r = guard(sql, POLICY)
    assert not r.allowed
    assert table in [x.detail.get("table") for x in r.reasons if x.code == Code.TABLE_NOT_ALLOWED]


def test_cte_name_shadowing_an_allowed_table_still_checks_body():
    r = guard("WITH customers AS (SELECT * FROM secrets) SELECT * FROM customers", POLICY)
    assert not r.allowed


def test_cte_name_does_not_leak_out_of_its_scope():
    sql = ("SELECT * FROM customers "
           "JOIN (WITH secrets AS (SELECT 1 AS id) SELECT * FROM secrets) x ON 1 = 1 "
           "JOIN secrets s ON 1 = 1")
    r = guard(sql, POLICY)
    assert not r.allowed
    assert r.reasons[0].detail == {"table": "secrets"}


def test_cte_referencing_earlier_cte():
    ok("WITH a AS (SELECT * FROM orders), b AS (SELECT * FROM a) SELECT * FROM b")


def test_recursive_cte():
    ok("WITH RECURSIVE n AS (SELECT 1 AS x UNION ALL SELECT x + 1 FROM n WHERE x < 5) SELECT * FROM n")


def test_blocked_schema_even_if_allowlisted():
    p = Policy(allowed_tables={"mysql.user"})
    assert Code.TABLE_NOT_ALLOWED in codes("SELECT * FROM mysql.user", p)


def test_qualified_allowlist_entry():
    p = Policy(allowed_tables={"analytics.events"})
    ok("SELECT * FROM analytics.events", p)
    assert Code.TABLE_NOT_ALLOWED in codes("SELECT * FROM events", p)


def test_table_functions_blocked():
    sql = "SELECT * FROM JSON_TABLE('[1]', '$[*]' COLUMNS (a INT PATH '$')) jt"
    assert not guard(sql, POLICY).allowed


def test_tables_reported():
    r = ok("SELECT * FROM customers c JOIN orders o ON o.customer_id = c.id")
    assert r.tables == ("customers", "orders")


# --- result shape ------------------------------------------------------------

def test_collects_all_reasons():
    r = guard("DELETE FROM secrets WHERE id = SLEEP(1)", POLICY)
    got = {x.code for x in r.reasons}
    assert {Code.DENIED_KEYWORD, Code.NOT_SELECT, Code.TABLE_NOT_ALLOWED} <= got


@pytest.mark.parametrize("sql,code", [
    ("", Code.EMPTY_QUERY),
    ("   ", Code.EMPTY_QUERY),
    ("SELECT * FROM", Code.PARSE_ERROR),
    ("SELECT 'unterminated", Code.LEX_ERROR),
])
def test_bad_input(sql, code):
    assert codes(sql) == [code]


def test_json_contract():
    blocked = json.loads(guard("SELECT * FROM secrets", POLICY).to_json())
    assert blocked["allowed"] is False and blocked["sql"] is None
    assert blocked["reasons"][0] == {
        "code": "TABLE_NOT_ALLOWED",
        "message": "table secrets is not on the allowlist",
        "detail": {"table": "secrets"},
    }
    allowed = json.loads(guard("SELECT * FROM customers", POLICY).to_json())
    assert allowed == {
        "allowed": True,
        "sql": "SELECT * FROM customers LIMIT 100",
        "reasons": [],
        "row_cap": 100,
        "tables": ["customers"],
    }
