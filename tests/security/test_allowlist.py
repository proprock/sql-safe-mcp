import pytest
from sqlglot import exp

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.parser import ParserLimits, parse_select, validate_allowlist

LIMITS = ParserLimits(max_sql_chars=4096, max_ast_nodes=500, max_joins=4, max_in_list_items=10)

COMPARATORS = ("=", "<>", "!=", "<", "<=", ">", ">=")

ALLOWED = {
    "columns": "SELECT a, b FROM dbo.t",
    "qualified column": "SELECT t.a FROM dbo.t AS t",
    "column alias": "SELECT a AS x FROM t",
    "bracket identifiers": "SELECT [a b] FROM [dbo].[t]",
    "star": "SELECT * FROM t",
    "table star": "SELECT t.* FROM t",
    "literals": "SELECT 1, 'x', NULL, -2",
    "count star": "SELECT COUNT(*) FROM t",
    "count star alias": "SELECT COUNT(*) AS n FROM t",
    "top": "SELECT TOP 5 a FROM t",
    "inner join": "SELECT a FROM t INNER JOIN u ON t.id = u.id",
    "plain join": "SELECT a FROM t JOIN u ON t.id = u.id",
    "left join": "SELECT a FROM t LEFT JOIN u ON t.id = u.id",
    "where and or": "SELECT a FROM t WHERE a = 1 AND (b <> 2 OR c >= 3)",
    "comparisons": "SELECT a FROM t WHERE a < 1 OR a <= 1 OR a > 1 OR a >= 1 OR a != 1",
    "in list": "SELECT a FROM t WHERE a IN (1, -2, 'x')",
    "is null": "SELECT a FROM t WHERE a IS NULL",
    "order by column": "SELECT a FROM t ORDER BY a DESC, t.b",
    "table alias": "SELECT x.a FROM t x",
    "join on and": "SELECT a FROM t JOIN u ON t.id = u.id AND t.b IS NULL",
    "join on or": "SELECT a FROM t JOIN u ON t.id = u.id OR t.b IN (1)",
    "join on paren": "SELECT a FROM t JOIN u ON (t.id = u.id)",
    "join on is null": "SELECT a FROM t JOIN u ON t.id IS NULL",
    "join on in": "SELECT a FROM t JOIN u ON t.id IN (1, 2)",
    "double parentheses": "SELECT a FROM t WHERE ((a = 1))",
    "nested predicates": (
        "SELECT a FROM t WHERE (a = 1 AND (b IS NULL OR c IN (1))) OR (d = 1 AND e IS NULL) "
        "AND (f = 2 OR (g = 3)) AND h IN (1) AND i IS NULL"
    ),
    "nested join predicates": (
        "SELECT a FROM t JOIN u ON ((t.id = u.id AND t.b IS NULL) OR (t.c IN (1) AND t.d = 2)) "
        "AND (t.e = 1 OR u.f IS NULL)"
    ),
    **{
        f"predicate chain {op}": f"SELECT a FROM t WHERE a {op} 1 AND b {op} 2 OR (c {op} 3)"
        for op in COMPARATORS
    },
    **{f"join on {op}": f"SELECT a FROM t JOIN u ON t.id {op} 1" for op in COMPARATORS},
    **{f"negative operand {op}": f"SELECT a FROM t WHERE a {op} -1" for op in COMPARATORS},
}

REJECTED = {
    "two statements": "SELECT 1; SELECT 2",
    "stacked delete": "SELECT 1; DELETE FROM t",
    "insert": "INSERT INTO t VALUES (1)",
    "update": "UPDATE t SET a = 1",
    "exec": "EXEC sp_who",
    "cte": "WITH x AS (SELECT 1 AS a) SELECT a FROM x",
    "scalar subquery": "SELECT (SELECT 1)",
    "in subquery": "SELECT a FROM t WHERE a IN (SELECT 1)",
    "exists": "SELECT a FROM t WHERE EXISTS (SELECT 1)",
    "derived table": "SELECT a FROM (SELECT a FROM t) AS d",
    "union": "SELECT a FROM t UNION SELECT a FROM u",
    "union all": "SELECT a FROM t UNION ALL SELECT a FROM u",
    "intersect": "SELECT a FROM t INTERSECT SELECT a FROM u",
    "except": "SELECT a FROM t EXCEPT SELECT a FROM u",
    "distinct": "SELECT DISTINCT a FROM t",
    "group by": "SELECT a FROM t GROUP BY a",
    "having": "SELECT a FROM t GROUP BY a HAVING a > 1",
    "count with group": "SELECT a, COUNT(*) FROM t GROUP BY a",
    "count column": "SELECT COUNT(a) FROM t",
    "count distinct": "SELECT COUNT(DISTINCT a) FROM t",
    "sum": "SELECT SUM(a) FROM t",
    "max": "SELECT MAX(a) FROM t",
    "scalar function": "SELECT LOWER(a) FROM t",
    "udf": "SELECT dbo.f(a) FROM t",
    "table valued function": "SELECT * FROM dbo.f(1)",
    "window": "SELECT ROW_NUMBER() OVER (ORDER BY a) FROM t",
    "case": "SELECT CASE WHEN a = 1 THEN 1 ELSE 0 END FROM t",
    "cast": "SELECT CAST(a AS int) FROM t",
    "arithmetic": "SELECT a + 1 FROM t",
    "select into": "SELECT a INTO x FROM t",
    "variable": "SELECT @v",
    "system variable": "SELECT @@version",
    "temp table": "SELECT a FROM #t",
    "global temp table": "SELECT a FROM ##t",
    "table variable": "SELECT a FROM @t",
    "cross database": "SELECT a FROM other.dbo.t",
    "four part name": "SELECT a FROM ls.other.dbo.t",
    "linked server": "SELECT a FROM [ls].[other].[dbo].[t]",
    "openrowset": "SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT 1')",
    "openquery": "SELECT * FROM OPENQUERY(ls, 'SELECT 1')",
    "cross apply": "SELECT a FROM t CROSS APPLY dbo.f(t.a) x",
    "outer apply": "SELECT a FROM t OUTER APPLY dbo.f(t.a) x",
    "pivot": "SELECT * FROM t PIVOT (COUNT(a) FOR b IN ([x])) p",
    "unpivot": "SELECT * FROM t UNPIVOT (v FOR c IN (a, b)) p",
    "table hint": "SELECT a FROM t WITH (NOLOCK)",
    "lock hint": "SELECT a FROM t WITH (UPDLOCK)",
    "option": "SELECT a FROM t OPTION (RECOMPILE)",
    "for xml": "SELECT a FROM t FOR XML AUTO",
    "for json": "SELECT a FROM t FOR JSON AUTO",
    "waitfor": "WAITFOR DELAY '0:0:5'",
    "full join": "SELECT a FROM t FULL JOIN u ON t.id = u.id",
    "right join": "SELECT a FROM t RIGHT JOIN u ON t.id = u.id",
    "cross join": "SELECT a FROM t CROSS JOIN u",
    "comma join": "SELECT a FROM t, u",
    "join without on": "SELECT a FROM t JOIN u",
    "join using": "SELECT a FROM t JOIN u USING (id)",
    "top percent": "SELECT TOP 5 PERCENT a FROM t",
    "top with ties": "SELECT TOP 5 WITH TIES a FROM t ORDER BY a",
    "top expression": "SELECT TOP (1 + 1) a FROM t",
    "offset fetch": "SELECT a FROM t ORDER BY a OFFSET 1 ROWS FETCH NEXT 2 ROWS ONLY",
    "like": "SELECT a FROM t WHERE a LIKE 'x%'",
    "between": "SELECT a FROM t WHERE a BETWEEN 1 AND 2",
    "not": "SELECT a FROM t WHERE NOT a = 1",
    "not in": "SELECT a FROM t WHERE a NOT IN (1)",
    "is not null": "SELECT a FROM t WHERE a IS NOT NULL",
    "is non-null": "SELECT a FROM t WHERE a IS 1",
    "order by expression": "SELECT a FROM t ORDER BY a + 1",
    "order by function": "SELECT a FROM t ORDER BY LOWER(a)",
    "order by literal": "SELECT a FROM t ORDER BY 1",
    "placeholder": "SELECT a FROM t WHERE a = :x",
    "table sample": "SELECT a FROM t TABLESAMPLE (10 PERCENT)",
    "system time": "SELECT a FROM t FOR SYSTEM_TIME ALL",
    "column alias list": "SELECT a FROM t AS x (c1)",
    "three part column": "SELECT dbo.t.a FROM t",
    "four part column": "SELECT other.dbo.t.a FROM t",
    "string plus": "SELECT 'a' + 'b'",
    "compare star": "SELECT a FROM t WHERE * = 1",
    "bracketed temp table": "SELECT a FROM [#t]",
    "bracketed table variable": "SELECT a FROM [@t]",
    "column as predicate": "SELECT a FROM t WHERE a",
    "column inside and": "SELECT a FROM t WHERE a AND b = 1",
    "column inside parentheses": "SELECT a FROM t WHERE (a)",
    "column as join condition": "SELECT a FROM t JOIN u ON a",
    "literal as predicate": "SELECT a FROM t WHERE 1",
    "null as predicate": "SELECT a FROM t WHERE NULL",
    "null compared": "SELECT a FROM t WHERE NULL = a",
    "literal is null": "SELECT a FROM t WHERE 1 IS NULL",
}


def parse(sql: str) -> exp.Select:
    return parse_select(sql, LIMITS)


@pytest.mark.parametrize("sql", ALLOWED.values(), ids=ALLOWED.keys())
def test_allowed(sql: str) -> None:
    assert isinstance(parse(sql), exp.Select)


@pytest.mark.parametrize("sql", REJECTED.values(), ids=REJECTED.keys())
def test_rejected(sql: str) -> None:
    with pytest.raises(DomainError) as info:
        parse(sql)
    assert info.value.code is ErrorCode.QUERY_REJECTED


def test_unknown_node_type_is_rejected() -> None:
    query = exp.select("a").from_("t").where(exp.Anonymous(this="f", expressions=[]))
    with pytest.raises(DomainError) as info:
        validate_allowlist(query)
    assert info.value.code is ErrorCode.QUERY_REJECTED


def test_unknown_non_empty_argument_is_rejected() -> None:
    query = exp.select("a").from_("t")
    query.set("kind", "STRUCT")
    with pytest.raises(DomainError):
        validate_allowlist(query)


def test_allowlist_can_admit_placeholders_after_rewrite() -> None:
    query = (
        exp.select("a")
        .from_("t")
        .where(exp.EQ(this=exp.column("a"), expression=exp.Placeholder(this="p")))
    )
    with pytest.raises(DomainError):
        validate_allowlist(query)
    validate_allowlist(query, allow_placeholders=True)
