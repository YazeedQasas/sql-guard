"""Policy (what is allowed) and result (what the guard decided) types."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Statement keywords and functions that never belong in a read-only query.
# Matched only against bare words outside string literals and quoted identifiers.
DEFAULT_DENIED_KEYWORDS: frozenset[str] = frozenset({
    # DML / DDL
    "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "TRUNCATE",
    "CREATE", "ALTER", "DROP", "RENAME",
    # privileges / admin
    "GRANT", "REVOKE", "SHUTDOWN", "KILL", "INSTALL", "UNINSTALL",
    "FLUSH", "RESET", "PURGE", "CHANGE", "OPTIMIZE", "REPAIR", "ANALYZE",
    # procedural / session
    "CALL", "EXEC", "EXECUTE", "PREPARE", "DEALLOCATE", "DO", "HANDLER",
    "SET", "USE", "LOCK", "UNLOCK",
    # transactions
    "START", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE", "XA",
    # file I/O
    "LOAD", "INTO", "OUTFILE", "DUMPFILE", "LOAD_FILE",
    # denial-of-service / side-effect functions
    "SLEEP", "BENCHMARK", "GET_LOCK", "RELEASE_LOCK", "RELEASE_ALL_LOCKS",
    "IS_FREE_LOCK", "IS_USED_LOCK", "SYS_EXEC", "SYS_EVAL",
})

DEFAULT_BLOCKED_SCHEMAS: frozenset[str] = frozenset({
    "mysql", "information_schema", "performance_schema", "sys",
})


@dataclass(frozen=True)
class Policy:
    """What a query is allowed to touch.

    allowed_tables: table names, optionally qualified as ``db.table``.
        An unqualified entry matches the table in the default database only.
    max_rows: the forced row cap (MySQL LIMIT).
    default_database: the database unqualified table names resolve to.
    """

    allowed_tables: frozenset[str]
    max_rows: int = 100
    default_database: str | None = None
    denied_keywords: frozenset[str] = DEFAULT_DENIED_KEYWORDS
    blocked_schemas: frozenset[str] = DEFAULT_BLOCKED_SCHEMAS

    def __post_init__(self) -> None:
        if self.max_rows < 1:
            raise ValueError("max_rows must be >= 1")
        object.__setattr__(self, "allowed_tables",
                           frozenset(t.strip().lower() for t in self.allowed_tables))
        object.__setattr__(self, "denied_keywords",
                           frozenset(k.strip().upper() for k in self.denied_keywords))
        object.__setattr__(self, "blocked_schemas",
                           frozenset(s.strip().lower() for s in self.blocked_schemas))
        if self.default_database:
            object.__setattr__(self, "default_database", self.default_database.lower())

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        denied = set(DEFAULT_DENIED_KEYWORDS)
        denied |= {k.upper() for k in data.get("extra_denied_keywords", [])}
        denied -= {k.upper() for k in data.get("allow_keywords", [])}
        return cls(
            allowed_tables=frozenset(data.get("allowed_tables", [])),
            max_rows=int(data.get("max_rows", 100)),
            default_database=data.get("default_database"),
            denied_keywords=frozenset(denied),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


# --- result -----------------------------------------------------------------

class Code:
    """Stable, machine-readable reason codes."""

    EMPTY_QUERY = "EMPTY_QUERY"
    LEX_ERROR = "LEX_ERROR"
    PARSE_ERROR = "PARSE_ERROR"
    COMMENT_NOT_ALLOWED = "COMMENT_NOT_ALLOWED"
    MULTIPLE_STATEMENTS = "MULTIPLE_STATEMENTS"
    DENIED_KEYWORD = "DENIED_KEYWORD"
    NOT_SELECT = "NOT_SELECT"
    TABLE_NOT_ALLOWED = "TABLE_NOT_ALLOWED"
    VARIABLE_NOT_ALLOWED = "VARIABLE_NOT_ALLOWED"


@dataclass(frozen=True)
class Reason:
    code: str
    message: str
    detail: dict = field(default_factory=dict)


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    sql: str | None                         # the safe, capped SELECT when allowed
    reasons: tuple[Reason, ...] = ()
    row_cap: int | None = None              # the LIMIT actually applied
    tables: tuple[str, ...] = ()            # tables the query reads

    def to_dict(self) -> dict:
        d = asdict(self)
        d["reasons"] = [asdict(r) for r in self.reasons]
        d["tables"] = list(self.tables)
        return d

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
