"""A deliberately small MySQL-aware scanner.

It does not try to understand SQL. It answers the questions the guard needs
answered *before* trusting a real parser:

* where are the comments (``--``, ``#``, ``/* */`` and MySQL's executable
  ``/*! */``)?
* where are the statement separators (``;``)?
* which bare words appear outside string literals and quoted identifiers?

String literals ('...' and "...") honour MySQL backslash escapes and doubled
quotes. Backtick identifiers honour doubled backticks.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class LexError(ValueError):
    def __init__(self, message: str, position: int):
        super().__init__(message)
        self.position = position


@dataclass
class ScanResult:
    words: list[tuple[str, int]] = field(default_factory=list)      # (UPPER word, offset)
    comments: list[tuple[str, int]] = field(default_factory=list)   # (marker, offset)
    semicolons: list[int] = field(default_factory=list)             # offsets
    variables: list[int] = field(default_factory=list)              # offsets of '@'


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch in "_$"


def scan(sql: str) -> ScanResult:
    out = ScanResult()
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        # --- comments -------------------------------------------------------
        if ch == "-" and nxt == "-":
            # MySQL only treats "-- " (with whitespace) as a comment, but "--" is
            # banned outright: generated SQL never needs it.
            out.comments.append(("--", i))
            j = sql.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if ch == "#":
            out.comments.append(("#", i))
            j = sql.find("\n", i)
            i = n if j == -1 else j + 1
            continue
        if ch == "/" and nxt == "*":
            marker = "/*!" if sql.startswith("/*!", i) else "/*"
            out.comments.append((marker, i))
            j = sql.find("*/", i + 2)
            if j == -1:
                raise LexError("unterminated block comment", i)
            i = j + 2
            continue

        # --- quoted strings / identifiers -----------------------------------
        if ch in ("'", '"', "`"):
            i = _skip_quoted(sql, i, ch)
            continue

        if ch == ";":
            out.semicolons.append(i)
            i += 1
            continue

        if ch == "@":
            out.variables.append(i)
            i += 2 if nxt == "@" else 1
            continue

        # --- bare words -----------------------------------------------------
        if _is_word_char(ch):
            start = i
            while i < n and _is_word_char(sql[i]):
                i += 1
            word = sql[start:i]
            if not word[0].isdigit():
                out.words.append((word.upper(), start))
            continue

        i += 1
    return out


def _skip_quoted(sql: str, start: int, quote: str) -> int:
    i, n = start + 1, len(sql)
    while i < n:
        ch = sql[i]
        if ch == "\\" and quote != "`":
            i += 2
            continue
        if ch == quote:
            if i + 1 < n and sql[i + 1] == quote:   # doubled quote = escaped quote
                i += 2
                continue
            return i + 1
        i += 1
    kind = "identifier" if quote == "`" else "string literal"
    raise LexError(f"unterminated {kind}", start)
