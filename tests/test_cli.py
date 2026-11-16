import json

from sql_guard.cli import EXIT_ALLOWED, EXIT_BLOCKED, EXIT_ERROR, main


def test_allowed(capsys):
    assert main(["check", "SELECT * FROM customers"]) == EXIT_ALLOWED
    out = json.loads(capsys.readouterr().out)
    assert out["sql"] == "SELECT * FROM customers LIMIT 100"


def test_blocked(capsys):
    assert main(["check", "DROP TABLE customers", "--compact"]) == EXIT_BLOCKED
    out = json.loads(capsys.readouterr().out)
    assert out["allowed"] is False
    assert {r["code"] for r in out["reasons"]} >= {"DENIED_KEYWORD", "NOT_SELECT"}


def test_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("SELECT * FROM orders LIMIT 5"))
    assert main(["check", "-"]) == EXIT_ALLOWED
    assert json.loads(capsys.readouterr().out)["row_cap"] == 5


def test_missing_policy(capsys):
    assert main(["check", "SELECT 1", "--policy", "nope.json"]) == EXIT_ERROR
    assert "could not load policy" in capsys.readouterr().out
