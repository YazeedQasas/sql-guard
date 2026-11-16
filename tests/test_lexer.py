import pytest

from sql_guard.lexer import LexError, scan


def words(sql):
    return [w for w, _ in scan(sql).words]


def test_words_outside_literals_only():
    assert words("SELECT 'DROP TABLE x' FROM t") == ["SELECT", "FROM", "T"]


def test_backslash_and_doubled_quote_escapes():
    assert words(r"SELECT 'it\'s; DELETE' , 'a''b; DROP' FROM t") == ["SELECT", "FROM", "T"]
    assert scan(r"SELECT 'x\';' FROM t").semicolons == []


def test_double_quoted_is_a_string_in_mysql():
    assert words('SELECT "update" FROM t') == ["SELECT", "FROM", "T"]


def test_backtick_identifiers_are_not_keywords():
    assert words("SELECT `delete`, `a``b` FROM t") == ["SELECT", "FROM", "T"]


@pytest.mark.parametrize("sql,marker", [
    ("SELECT 1 -- hi", "--"),
    ("SELECT 1 --", "--"),
    ("SELECT 1 # hi", "#"),
    ("SELECT /* x */ 1", "/*"),
    ("SELECT /*!50000 1 */", "/*!"),
])
def test_comments_detected(sql, marker):
    assert [m for m, _ in scan(sql).comments] == [marker]


def test_comment_markers_inside_strings_are_ignored():
    r = scan("SELECT '-- # /* */' FROM t")
    assert r.comments == []


def test_semicolons():
    assert scan("SELECT 1; SELECT 2;").semicolons == [8, 18]


def test_numbers_are_not_words():
    assert words("SELECT 1e5, 0x1F") == ["SELECT"]


@pytest.mark.parametrize("sql", ["SELECT 'abc", "SELECT `abc", "SELECT /* abc"])
def test_unterminated_raises(sql):
    with pytest.raises(LexError):
        scan(sql)
