"""The guard: block with machine-readable reasons, or return a safe capped SELECT."""

from __future__ import annotations

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from .lexer import LexError, scan
from .policy import Code, GuardResult, Policy, Reason

DIALECT = "mysql"

# Query roots that are reads. Anything else (Insert, Update, Command, Show...) is not.
_READ_ROOTS = (exp.Select, exp.Union, exp.Intersect, exp.Except)

# Node types that must never appear anywhere in the tree.
_WRITE_NODES: tuple[type[exp.Expression], ...] = tuple(
    t for t in (
        getattr(exp, name, None) for name in (
            "Insert", "Update", "Delete", "Merge", "Create", "Drop", "Alter",
            "TruncateTable", "Command", "Set", "Use", "Grant", "Revoke",
            "LoadData", "Into", "Lock", "Transaction", "Commit", "Rollback",
        )
    ) if t is not None
)


def guard(sql: str, policy: Policy) -> GuardResult:
    """Check ``sql`` against ``policy``.

    Every check runs, so a blocked result lists every problem found, not just the
    first one. Only when nothing is wrong is the rewritten, row-capped SQL returned.
    """
    reasons: list[Reason] = []

    if sql is None or not sql.strip():
        return _blocked([Reason(Code.EMPTY_QUERY, "query is empty")])

    # --- 1. lexical checks (comments, statement count, denylist) ------------
    try:
        scanned = scan(sql)
    except LexError as e:
        return _blocked([Reason(Code.LEX_ERROR, str(e), {"position": e.position})])

    for marker, pos in scanned.comments:
        reasons.append(Reason(
            Code.COMMENT_NOT_ALLOWED,
            f"comments are not allowed (found {marker!r})",
            {"marker": marker, "position": pos},
        ))

    body = sql.rstrip()
    separators = list(scanned.semicolons)
    if separators and separators[-1] == len(body) - 1:
        separators.pop()                      # one trailing ';' is fine
        body = body[:-1]
    if separators:
        reasons.append(Reason(
            Code.MULTIPLE_STATEMENTS,
            "only a single statement is allowed",
            {"positions": separators},
        ))

    seen: set[str] = set()
    for word, pos in scanned.words:
        if word in policy.denied_keywords and word not in seen:
            seen.add(word)
            reasons.append(Reason(
                Code.DENIED_KEYWORD,
                f"keyword {word} is not allowed",
                {"keyword": word, "position": pos},
            ))

    for pos in scanned.variables:
        reasons.append(Reason(
            Code.VARIABLE_NOT_ALLOWED,
            "user and system variables (@x, @@x) are not allowed",
            {"position": pos},
        ))
        break  # one is enough

    # Comments and stacked statements mean the text is hostile or broken; the
    # parser would only add noise (or, worse, silently drop a comment).
    if scanned.comments or separators:
        return _blocked(reasons)

    # --- 2. structural checks (AST) -----------------------------------------
    try:
        statements = [s for s in sqlglot.parse(body, read=DIALECT) if s is not None]
    except (ParseError, TokenError) as e:
        reasons.append(Reason(Code.PARSE_ERROR, "query could not be parsed", _parse_error_detail(e)))
        return _blocked(reasons)

    if len(statements) != 1:
        reasons.append(Reason(Code.MULTIPLE_STATEMENTS, "only a single statement is allowed",
                              {"statements": len(statements)}))
        return _blocked(reasons)

    tree = statements[0]
    reasons.extend(_check_select_only(tree))
    tables, table_reasons = _check_tables(tree, policy)
    reasons.extend(table_reasons)

    if reasons:
        return _blocked(reasons, tables)

    # --- 3. rewrite with the forced row cap ---------------------------------
    cap = _apply_row_cap(tree, policy.max_rows)
    return GuardResult(
        allowed=True,
        sql=tree.sql(dialect=DIALECT),
        reasons=(),
        row_cap=cap,
        tables=tuple(tables),
    )


# --- checks -----------------------------------------------------------------

def _check_select_only(tree: exp.Expression) -> list[Reason]:
    reasons: list[Reason] = []
    if not isinstance(tree, _READ_ROOTS):
        reasons.append(Reason(Code.NOT_SELECT, "only SELECT queries are allowed",
                              {"statement": type(tree).__name__.upper()}))
        return reasons
    found: set[str] = set()
    for node in tree.walk():
        if isinstance(node, _WRITE_NODES):
            name = type(node).__name__.upper()
            if name.startswith("LOCK"):
                name = "LOCK"
            if name not in found:
                found.add(name)
                reasons.append(Reason(Code.NOT_SELECT, f"{name} is not allowed inside a SELECT",
                                      {"node": name}))
        if isinstance(node, exp.Select) and node.args.get("locks") and "LOCK" not in found:
            found.add("LOCK")
            reasons.append(Reason(Code.NOT_SELECT, "locking reads (FOR UPDATE / FOR SHARE) are not allowed",
                                  {"node": "LOCK"}))
    return reasons


def _check_tables(tree: exp.Expression, policy: Policy) -> tuple[list[str], list[Reason]]:
    tables: list[str] = []
    reasons: list[Reason] = []
    for table in tree.find_all(exp.Table):
        name = table.name.lower()
        db = (table.db or "").lower()
        if not name:
            # e.g. a table function; it has no name to allowlist
            reasons.append(Reason(Code.TABLE_NOT_ALLOWED, "table expression is not allowed",
                                  {"table": table.sql(dialect=DIALECT)}))
            continue
        if not db and _is_cte_reference(table, name):
            continue
        qualified = f"{db}.{name}" if db else name
        if qualified not in tables:
            tables.append(qualified)
        if not _table_allowed(db, name, policy):
            reasons.append(Reason(Code.TABLE_NOT_ALLOWED, f"table {qualified} is not on the allowlist",
                                  {"table": qualified}))
    # de-duplicate reasons for the same table
    unique: dict[str, Reason] = {}
    for r in reasons:
        unique.setdefault(r.detail.get("table", ""), r)
    return tables, list(unique.values())


def _is_cte_reference(table: exp.Table, name: str) -> bool:
    """True only if a WITH clause that encloses this table defines ``name``.

    Scope matters: a CTE called ``secrets`` inside one subquery must not
    exempt a real ``secrets`` table referenced elsewhere in the query.
    """
    node = table.parent
    while node is not None:
        # the arg is "with_" in newer sqlglot, "with" in older releases
        with_ = node.args.get("with_") or node.args.get("with")
        if isinstance(with_, exp.With):
            if any(cte.alias_or_name.lower() == name for cte in with_.expressions):
                return True
        node = node.parent
    return False


def _table_allowed(db: str, name: str, policy: Policy) -> bool:
    if db in policy.blocked_schemas:
        return False
    if db:
        if f"{db}.{name}" in policy.allowed_tables:
            return True
        # db-qualified reference to the default database counts as unqualified
        return db == policy.default_database and name in policy.allowed_tables
    return name in policy.allowed_tables


# --- rewrite ----------------------------------------------------------------

def _apply_row_cap(tree: exp.Expression, max_rows: int) -> int:
    """Force LIMIT <= max_rows on the outermost query. Returns the cap applied."""
    limit = tree.args.get("limit")
    current = _literal_int(limit.expression) if isinstance(limit, exp.Limit) else None
    if current is not None and 0 <= current <= max_rows:
        return current
    if isinstance(limit, exp.Limit):
        limit.set("expression", exp.Literal.number(max_rows))
    else:
        tree.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
    return max_rows


def _literal_int(node: exp.Expression | None) -> int | None:
    if isinstance(node, exp.Literal) and not node.is_string:
        try:
            return int(node.this)
        except ValueError:
            return None
    return None


# --- helpers ----------------------------------------------------------------

def _blocked(reasons: list[Reason], tables: list[str] | None = None) -> GuardResult:
    return GuardResult(allowed=False, sql=None, reasons=tuple(reasons), tables=tuple(tables or ()))


def _parse_error_detail(e: Exception) -> dict:
    errors = getattr(e, "errors", None)
    if errors:
        first = errors[0]
        return {k: first.get(k) for k in ("description", "line", "col") if first.get(k) is not None}
    return {"description": str(e).splitlines()[0] if str(e) else type(e).__name__}
