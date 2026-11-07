"""Exact wording of every fixed error and message the security layer can produce."""

from __future__ import annotations

import copy
import pickle
import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from support import ALIAS, OWN, RUNTIME, SpyConnection, SpyResult, validate

from sql_safe_mcp.errors import DomainError, ErrorCode
from sql_safe_mcp.security.executor import execute_validated
from sql_safe_mcp.security.parser import REJECT_HINT, reject
from sql_safe_mcp.security.reasons import Reason
from sql_safe_mcp.security.tokens import TokenCodec, TokenKeyRegistry
from sql_safe_mcp.security.validated_query import ValidatedQuery


@contextmanager
def raises_exact(kind: type[BaseException], message: str) -> Iterator[None]:
    with pytest.raises(kind) as info:
        yield
    assert str(info.value) == message


def message_of(sql: str) -> str:
    with pytest.raises(DomainError) as info:
        validate(sql)
    assert info.value.code is ErrorCode.QUERY_REJECTED
    assert info.value.hint == REJECT_HINT
    return info.value.public_message


def test_reject_builds_the_documented_error() -> None:
    error = reject(Reason.ONE_STATEMENT)
    assert error.code is ErrorCode.QUERY_REJECTED
    assert error.public_message == "Query rejected: exactly one statement is required."
    assert error.hint == "Rewrite the operation as a single, simpler SELECT query."
    assert error.retryable is False
    assert error.correlation_id is None


def test_reject_appends_a_detail_name() -> None:
    assert reject(Reason.NODE_UNSUPPORTED, "Lower").public_message == (
        "Query rejected: unsupported construct: Lower."
    )


def test_reject_accepts_only_a_fixed_reason() -> None:
    for free_text in ("free text", None, 5):
        with raises_exact(TypeError, "reject() takes a Reason"):
            reject(free_text)  # ty: ignore[invalid-argument-type]


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("SELECT LOWER(Name) FROM Users", "unsupported construct: Lower"),
        ("SELECT Id FROM Users WITH (NOLOCK)", "unsupported option: Table.hints"),
        ("SELECT Id FROM Users GROUP BY Id", "unsupported option: Select.group"),
        ("SELECT Id FROM Users OPTION (MAXDOP 1)", "unsupported option: Select.options"),
    ],
)
def test_unsupported_constructs_name_the_offender(sql: str, expected: str) -> None:
    assert message_of(sql) == f"Query rejected: {expected}."


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        ("SELECT Id FROM Users; SELECT 1", Reason.ONE_STATEMENT),
        ("", Reason.ONE_STATEMENT),
        ("DELETE FROM Users", Reason.SELECT_ONLY),
        ("SELECT (", Reason.PARSE_FAILED),
        ("SELECT COUNT(Id) FROM Users", Reason.COUNT_STAR_ONLY),
        ("SELECT Id FROM Users WHERE * = 1", Reason.STAR_COMPARISON),
        ("SELECT Id FROM Users WHERE Name IS 1", Reason.IS_NULL_ONLY),
        ("SELECT TOP 5.5 Id FROM Users", Reason.TOP_INTEGER_ONLY),
        ("SELECT -Name FROM Users", Reason.NEGATION_NUMERIC_ONLY),
        ("SELECT Id FROM Users u JOIN Orders o", Reason.JOIN_NEEDS_ON),
        ("SELECT Id FROM Users u FULL JOIN Orders o ON 1 = 1", Reason.JOIN_TYPE_UNSUPPORTED),
        ("SELECT Id FROM Users ORDER BY 1", Reason.ORDER_DIRECT_COLUMNS_ONLY),
        ("SELECT Id FROM Users WHERE Id IN (Id)", Reason.IN_LITERALS_ONLY),
        ("SELECT Id FROM @t", Reason.TABLE_UNSUPPORTED),
        ("SELECT Id FROM Nope", Reason.TABLE_NOT_FOUND),
        ("SELECT Id FROM Items", Reason.TABLE_NOT_FOUND),
        ("SELECT Nope FROM Users", Reason.COLUMN_AMBIGUOUS),
        ("SELECT x.Id FROM Users u", Reason.QUALIFIER_UNKNOWN),
        ("SELECT u.Nope FROM Users u", Reason.COLUMN_NOT_FOUND),
        ("SELECT * FROM Users JOIN Users ON 1 = 1", Reason.DUPLICATE_BINDING),
        ("SELECT COUNT(*) AS n FROM Users ORDER BY n", Reason.ORDER_OUTPUT_AMBIGUOUS),
        ("SELECT Email FROM Users ORDER BY Id, Email", Reason.PROTECTED_POSITION),
        ("SELECT Id FROM Users WHERE Email = 'plain'", Reason.PROTECTED_NEEDS_TOKEN),
        ("SELECT Id FROM Users WHERE Name = 'pii:v1:AAAA'", Reason.TOKEN_OUTSIDE_PROTECTED),
        (f"SELECT Id FROM Users WHERE Email = '{OWN.encrypt(1)}'", Reason.TOKEN_TYPE_MISMATCH),
        ("SELECT Email FROM Contacts", Reason.COLUMN_DENIED),
        ("SELECT * FROM Contacts", Reason.COLUMN_DENIED),
    ],
)
def test_reasons_are_reported_verbatim(sql: str, reason: Reason) -> None:
    assert message_of(sql) == f"Query rejected: {reason.value}."


def test_domain_conflict_text_is_pinned() -> None:
    assert Reason.DOMAIN_CONFLICT.value == (
        "pii rules of different token domains match the same column"
    )


def test_column_denied_text_is_pinned() -> None:
    assert Reason.COLUMN_DENIED.value == "a denied column cannot be referenced"


def test_limits_are_reported_verbatim() -> None:
    assert message_of("SELECT Id FROM Users" + " " * RUNTIME.max_sql_chars) == (
        f"Query rejected: {Reason.LIMIT_CHARS.value}."
    )
    joins = "".join(f" JOIN Orders o{i} ON o{i}.Id = u.Id" for i in range(RUNTIME.max_joins + 1))
    assert message_of(f"SELECT u.Id FROM Users u{joins}") == (
        f"Query rejected: {Reason.LIMIT_JOINS.value}."
    )
    items = ", ".join(str(i) for i in range(RUNTIME.max_in_list_items + 1))
    assert message_of(f"SELECT Id FROM Users WHERE Id IN ({items})") == (
        f"Query rejected: {Reason.LIMIT_IN_LIST.value}."
    )
    columns = ", ".join(["Id"] * (RUNTIME.max_ast_nodes // 2 + 1))
    assert message_of(f"SELECT {columns} FROM Users") == (
        f"Query rejected: {Reason.LIMIT_NODES.value}."
    )


def test_invalid_token_error_is_exact() -> None:
    with pytest.raises(DomainError) as info:
        OWN.decrypt("nope")
    error = info.value
    assert error.code is ErrorCode.INVALID_PII_TOKEN
    assert error.public_message == "The PII token is invalid for this server."
    assert error.hint == "Use a token returned by execute_sql for the same server alias."
    assert error.retryable is False
    assert error.correlation_id is None


def test_unsupported_protected_value_error_is_exact() -> None:
    with pytest.raises(DomainError) as info:
        OWN.encrypt(object())
    assert info.value.code is ErrorCode.QUERY_REJECTED
    assert info.value.public_message == (
        "Query rejected: a protected column contains a value that cannot be tokenized."
    )
    assert info.value.hint == "Do not select this protected column."


def test_missing_key_registry_error_is_exact() -> None:
    with pytest.raises(DomainError) as info:
        TokenKeyRegistry({}).codec_for("x")
    assert info.value.code is ErrorCode.ACCESS_LEVEL_DENIED
    assert info.value.public_message == "PII tokens are not available for this server."
    assert info.value.hint == "Use a server configured with access_level all_pii_safe."


def test_row_limit_errors_are_exact() -> None:
    with pytest.raises(DomainError) as low:
        validate("SELECT Id FROM Users", max_rows=0)
    assert low.value.code is ErrorCode.INVALID_ARGUMENT
    assert low.value.public_message == "max_rows must be at least 1."
    assert low.value.hint == f"Use a value between 1 and {RUNTIME.hard_max_rows}."
    with pytest.raises(DomainError) as high:
        validate("SELECT Id FROM Users", max_rows=RUNTIME.hard_max_rows + 1)
    assert high.value.code is ErrorCode.RESULT_LIMIT_EXCEEDED
    assert high.value.public_message == (
        f"max_rows exceeds the configured hard limit of {RUNTIME.hard_max_rows}."
    )
    assert high.value.hint == f"Use a value between 1 and {RUNTIME.hard_max_rows}."


def test_the_hard_limit_itself_is_accepted() -> None:
    assert validate("SELECT Id FROM Users", max_rows=RUNTIME.hard_max_rows).max_rows == (
        RUNTIME.hard_max_rows
    )
    assert validate("SELECT Id FROM Users", max_rows=1).max_rows == 1


def test_validated_query_refuses_forgery_copy_and_serialization_with_clear_messages() -> None:
    query = validate("SELECT Id FROM Users")
    forge: Any = ValidatedQuery
    with raises_exact(TypeError, "ValidatedQuery can only be issued by the validation pipeline"):
        forge(
            object(),
            alias="a",
            database="d",
            ast=None,
            sql="",
            parameters=(),
            outputs=(),
            max_rows=1,
            min_count_cell=0,
        )
    with raises_exact(TypeError, "ValidatedQuery cannot be copied"):
        copy.copy(query)
    with raises_exact(TypeError, "ValidatedQuery cannot be copied"):
        copy.deepcopy(query)
    with raises_exact(TypeError, "ValidatedQuery cannot be serialized"):
        pickle.dumps(query)
    with raises_exact(AttributeError, "ValidatedQuery is read-only"):
        query.__setattr__("sql", "x")
    with raises_exact(AttributeError, "ValidatedQuery is read-only"):
        query.__delattr__("sql")


def test_executor_error_messages_are_exact() -> None:
    connection = SpyConnection()
    with raises_exact(TypeError, "the executor accepts only ValidatedQuery"):
        execute_validated(connection, "SELECT 1", OWN)  # ty: ignore[invalid-argument-type]
    with raises_exact(TypeError, "the token codec belongs to a different server alias"):
        execute_validated(
            connection, validate("SELECT Id FROM Users"), TokenCodec("other", b"k" * 32)
        )
    bad = SpyConnection(SpyResult(["Id"], [(object(),)]))
    with pytest.raises(DomainError) as info:
        execute_validated(bad, validate("SELECT Id FROM Users"), OWN)
    assert info.value.code is ErrorCode.DATABASE_ERROR
    assert info.value.public_message == "The result contains a value type that is not supported."
    assert info.value.hint == "Select different columns."


def test_alias_is_reported_by_the_query_and_the_codec() -> None:
    query = validate("SELECT Id FROM Users")
    assert query.alias == ALIAS == OWN.alias
    assert re.fullmatch(
        r"ValidatedQuery\(alias='srv', database='app', outputs=1, parameters=0\)", repr(query)
    )


def test_token_type_mismatch_text_is_pinned() -> None:
    assert Reason.TOKEN_TYPE_MISMATCH.value == (
        "a PII token does not match the type of the protected column"
    )
