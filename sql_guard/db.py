"""Run guarded SQL on a read-only MySQL connection.

This is the second layer of defence. Even if a query got past the guard:
* the MySQL user only has SELECT on the allowlisted tables (see sql/setup.sql),
* every query runs inside START TRANSACTION READ ONLY and is rolled back,
* max_execution_time stops runaway SELECTs,
* PyMySQL's default client flags do not enable multi-statements or LOCAL INFILE,
* rows are fetched with fetchmany(row_cap), so the cap holds client-side too.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import pymysql

from .guard import guard
from .policy import GuardResult, Policy


@dataclass(frozen=True)
class ConnectionSettings:
    host: str = "localhost"
    port: int = 3306
    user: str = "sqlguard_ro"
    password: str = field(default="", repr=False)
    database: str = "sqlguard_demo"
    timeout_ms: int = 5000

    @classmethod
    def from_env(cls) -> "ConnectionSettings":
        e = os.environ
        return cls(
            host=e.get("SQLGUARD_DB_HOST", cls.host),
            port=int(e.get("SQLGUARD_DB_PORT", cls.port)),
            user=e.get("SQLGUARD_DB_USER", cls.user),
            password=e.get("SQLGUARD_DB_PASSWORD", ""),
            database=e.get("SQLGUARD_DB_NAME", cls.database),
            timeout_ms=int(e.get("SQLGUARD_DB_TIMEOUT_MS", cls.timeout_ms)),
        )


@dataclass(frozen=True)
class QueryResult:
    columns: list[str]
    rows: list[list]

    def to_dict(self) -> dict:
        return {"columns": self.columns, "rows": self.rows, "row_count": len(self.rows)}


def connect(settings: ConnectionSettings) -> pymysql.connections.Connection:
    return pymysql.connect(
        host=settings.host,
        port=settings.port,
        user=settings.user,
        password=settings.password,
        database=settings.database,
        autocommit=False,
        local_infile=False,
        connect_timeout=5,
        charset="utf8mb4",
    )


def execute_guarded(result: GuardResult, settings: ConnectionSettings) -> QueryResult:
    """Execute SQL that ``guard`` already approved. Refuses anything else."""
    if not result.allowed or not result.sql:
        raise ValueError("refusing to execute a query the guard did not allow")

    conn = connect(settings)
    try:
        with conn.cursor() as cur:
            cur.execute("SET SESSION max_execution_time = %s", (int(settings.timeout_ms),))
            cur.execute("START TRANSACTION READ ONLY")
            try:
                cur.execute(result.sql)
                columns = [d[0] for d in cur.description or ()]
                cap = result.row_cap if result.row_cap is not None else 0
                rows = [list(_jsonable(v) for v in row) for row in cur.fetchmany(cap)]
            finally:
                conn.rollback()
        return QueryResult(columns=columns, rows=rows)
    finally:
        conn.close()


def run(sql: str, policy: Policy, settings: ConnectionSettings) -> tuple[GuardResult, QueryResult | None]:
    """Guard ``sql`` and, if allowed, execute it read-only."""
    result = guard(sql, policy)
    if not result.allowed:
        return result, None
    return result, execute_guarded(result, settings)


def _jsonable(v):
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, bytes):
        return v.hex()
    return str(v)   # Decimal, date, datetime, ...
