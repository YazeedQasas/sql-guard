"""Command line: sql-guard check "<sql>" [--policy policy.json] [--execute]

Exit codes: 0 allowed, 2 blocked, 1 error (bad policy, DB failure, ...).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .guard import guard
from .policy import Policy

EXIT_ALLOWED, EXIT_ERROR, EXIT_BLOCKED = 0, 1, 2


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Minimal .env support: KEY=VALUE lines; real env vars win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sql-guard", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="guard a query (and optionally run it read-only)")
    check.add_argument("sql", help='the SQL to check, or "-" to read it from stdin')
    check.add_argument("--policy", default="policy.json", help="policy JSON file (default: policy.json)")
    check.add_argument("--execute", action="store_true", help="run the query on the read-only connection if allowed")
    check.add_argument("--compact", action="store_true", help="single-line JSON")
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    indent = None if args.compact else 2

    sql = sys.stdin.read() if args.sql == "-" else args.sql
    try:
        policy = Policy.from_file(args.policy)
    except (OSError, ValueError) as e:
        print(json.dumps({"error": f"could not load policy: {e}"}, indent=indent))
        return EXIT_ERROR

    result = guard(sql, policy)
    out = result.to_dict()

    if result.allowed and args.execute:
        _load_dotenv()
        from .db import ConnectionSettings, execute_guarded   # imported lazily: pymysql only needed here
        try:
            out["result"] = execute_guarded(result, ConnectionSettings.from_env()).to_dict()
        except Exception as e:  # report DB errors as JSON, not a traceback
            out["error"] = f"{type(e).__name__}: {e}"
            print(json.dumps(out, indent=indent))
            return EXIT_ERROR

    print(json.dumps(out, indent=indent, ensure_ascii=False))
    return EXIT_ALLOWED if result.allowed else EXIT_BLOCKED


if __name__ == "__main__":
    sys.exit(main())
