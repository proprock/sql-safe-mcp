from __future__ import annotations

import random
from typing import Any

import pytest
import yaml

from sql_safe_mcp.config import PiiConfig, PiiRule, PiiScopeRule
from sql_safe_mcp.pii_scaffold import (
    ScaffoldCatalog,
    ScaffoldColumn,
    ScaffoldTable,
    classify_column,
    render_scaffold,
)
from sql_safe_mcp.security.rules import rule_matches_table
from sql_safe_mcp.security.schema import TypeClass

ENFORCED = PiiConfig(rules=[PiiRule(database="*", table="enforced", columns=["secret"])])


def col(name: str, type_class: TypeClass = "integer", *, pk: bool = False) -> ScaffoldColumn:
    return ScaffoldColumn(name=name, type_class=type_class, primary_key=pk)


def table(schema: str | None, name: str, *columns: ScaffoldColumn) -> ScaffoldTable:
    return (schema, name, tuple(columns))


def catalog(
    databases: dict[str, list[ScaffoldTable]], visible: int | None = None
) -> ScaffoldCatalog:
    return ScaffoldCatalog(databases=databases, visible=visible or len(databases))


def draft(
    databases: dict[str, list[ScaffoldTable]],
    pii: PiiConfig = ENFORCED,
    visible: int | None = None,
) -> tuple[str, dict[str, Any]]:
    text = render_scaffold("alias", catalog(databases, visible), pii)
    loaded = yaml.safe_load(text)
    assert isinstance(loaded, dict)
    return text, loaded


# --- classification ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("column", "expected"),
    [
        (col("Photo", "binary"), "deny"),
        (col("Payload", "binary"), "deny"),
        (col("DoctorNotes", "string"), "deny"),
        (col("Comment", "integer"), "deny"),
        (col("memo_flag", "bool"), "deny"),
        (col("AttachmentCount", "integer"), "deny"),
        (col("photo_id", "integer", pk=True), "deny"),
        (col("EmailCount", "integer"), "token"),
        (col("PhoneVerified", "bool"), "token"),
        (col("Title", "string"), "token"),
        (col("Created", "datetime"), "token"),
        (col("Born", "date"), "token"),
        (col("At", "time"), "token"),
        (col("Ref", "uuid"), "token"),
        (col("Shape", "other"), "token"),
        (col("Id", "string", pk=True), "token"),
        (col("Id", "integer", pk=True), "key"),
        (col("CustomerId", "integer"), "key"),
        (col("customer_id", "decimal"), "key"),
        (col("Amount", "integer"), "open"),
        (col("Price", "decimal"), "open"),
        (col("Ratio", "float"), "open"),
        (col("Active", "bool"), "open"),
    ],
    ids=lambda value: getattr(value, "name", str(value)),
)
def test_classification_follows_the_card(column: ScaffoldColumn, expected: str) -> None:
    assert classify_column(column) == expected


# --- folding ----------------------------------------------------------------------------------


def test_the_same_table_in_two_databases_is_one_entry_without_a_database() -> None:
    orders = table("dbo", "Orders", col("Id", pk=True), col("Amount"), col("Notes", "string"))
    _, loaded = draft({"A": [orders], "B": [orders]})

    assert loaded["mode"] == "deny-by-default"
    assert loaded["exposed_columns"] == [
        {"schema": "dbo", "table": "Orders", "columns": ["Amount"]}
    ]
    assert loaded["deny"] == [{"schema": "dbo", "table": "Orders", "columns": ["Notes"]}]


def test_a_column_missing_from_one_database_is_not_offered_and_is_named() -> None:
    a = table("dbo", "Orders", col("Amount"), col("Discount"))
    b = table("dbo", "Orders", col("Amount"))
    text, loaded = draft({"A": [a], "B": [b]})

    assert loaded["exposed_columns"] == [
        {"schema": "dbo", "table": "Orders", "columns": ["Amount"]}
    ]
    assert "# only in A: dbo.Orders.Discount" in text


def test_a_table_in_one_database_only_is_offered_when_all_its_columns_are_there() -> None:
    _, loaded = draft(
        {"A": [table("dbo", "Orders", col("Amount"))], "B": [table("dbo", "Other", col("Qty"))]}
    )

    assert {entry["table"] for entry in loaded["exposed_columns"]} == {"Orders", "Other"}


def test_the_same_table_name_in_two_schemas_is_not_merged() -> None:
    _, loaded = draft(
        {"A": [table("alpha", "Users", col("Amount")), table("beta", "Users", col("Qty"))]}
    )

    assert loaded["exposed_columns"] == [
        {"schema": "alpha", "table": "Users", "columns": ["Amount"]},
        {"schema": "beta", "table": "Users", "columns": ["Qty"]},
    ]


def test_grouping_ignores_case_and_the_spelling_comes_from_the_first_database_by_name() -> None:
    _, loaded = draft(
        {
            "b": [table("DBO", "ORDERS", col("AMOUNT"))],
            "A": [table("dbo", "Orders", col("Amount"))],
        }
    )

    assert loaded["exposed_columns"] == [
        {"schema": "dbo", "table": "Orders", "columns": ["Amount"]}
    ]


def test_a_type_that_differs_between_databases_is_not_opened() -> None:
    a = table(None, "t", col("Value", "integer"))
    b = table(None, "t", col("Value", "string"))
    _, loaded = draft({"A": [a], "B": [b]})

    assert loaded["exposed_columns"] == []


def test_a_deny_match_in_one_database_denies_the_column_everywhere() -> None:
    a = table(None, "t", col("Payload", "binary"))
    b = table(None, "t", col("Payload", "integer"))
    _, loaded = draft({"A": [a], "B": [b]})

    assert loaded["deny"] == [{"table": "t", "columns": ["Payload"]}]


def test_mysql_tables_have_no_schema_key() -> None:
    _, loaded = draft({"shop": [table(None, "orders", col("amount"))]})

    assert loaded["exposed_columns"] == [{"table": "orders", "columns": ["amount"]}]


def test_key_columns_are_a_commented_block_with_the_safe_harbor_caveat() -> None:
    text, loaded = draft({"A": [table("dbo", "Orders", col("Id", pk=True), col("Amount"))]})

    assert loaded["exposed_columns"] == [
        {"schema": "dbo", "table": "Orders", "columns": ["Amount"]}
    ]
    assert "# Key columns" in text
    assert "#   - {schema: dbo, table: Orders, columns: [Id]}" in text
    assert "Safe Harbor identifier (R)" in text
    assert "docs/health-data.md" in text


def test_columns_the_existing_rules_protect_are_not_offered() -> None:
    pii = PiiConfig(
        rules=[PiiRule(database="*", table="Orders", columns=["Amount"])],
        deny=[PiiScopeRule(table="Orders", columns=["Qty"])],
    )
    text, loaded = draft(
        {"A": [table(None, "Orders", col("Amount"), col("Qty"), col("Total"))]}, pii
    )

    assert loaded["exposed_columns"] == [{"table": "Orders", "columns": ["Total"]}]
    assert loaded["deny"] == []
    assert "# protected by an existing rule: Orders.Amount, Orders.Qty" in text


def test_a_rule_for_another_database_still_keeps_the_column_out() -> None:
    pii = PiiConfig(rules=[PiiRule(database="A", table="t", columns=["Amount"])])
    _, loaded = draft(
        {"A": [table(None, "t", col("Amount"))], "B": [table(None, "t", col("Amount"))]}, pii
    )

    assert loaded["exposed_columns"] == []


# --- names that are patterns or ambiguous -----------------------------------------------------


@pytest.mark.parametrize(
    ("name", "decoy"), [("Ref*", "Refx"), ("a?b", "axb"), ("x[1]", "x1"), ("[z]", "z")]
)
def test_a_table_name_with_pattern_characters_matches_only_itself(name: str, decoy: str) -> None:
    _, loaded = draft({"A": [table(None, name, col("Amount")), table(None, decoy, col("Qty"))]})

    entries = {entry["table"]: entry for entry in loaded["exposed_columns"]}
    assert len(entries) == 2
    rule = PiiScopeRule.model_validate(
        {"table": next(key for key in entries if key != decoy), "columns": ["Amount"]}
    )
    assert rule_matches_table(rule, "A", None, name)
    assert not rule_matches_table(rule, "A", None, decoy)
    assert not rule_matches_table(rule, "A", None, name + "tail")


def test_a_column_name_with_a_star_is_never_listed_and_is_named() -> None:
    text, loaded = draft({"A": [table(None, "t", col("a*b"), col("Amount"))]})

    assert loaded["exposed_columns"] == [{"table": "t", "columns": ["Amount"]}]
    assert "# not listable: t.a?b" in text  # names in comments are sanitized


def test_columns_that_differ_only_by_case_are_not_listed() -> None:
    text, loaded = draft({"A": [table(None, "t", col("amount"), col("AMOUNT"), col("Qty"))]})

    assert loaded["exposed_columns"] == [{"table": "t", "columns": ["Qty"]}]
    assert "# not listable: t.AMOUNT, t.amount" in text


# --- output contract --------------------------------------------------------------------------

TRAPS = [
    "No",
    "yes",
    "null",
    "~",
    "1e3",
    "0x1F",
    "-",
    "#x",
    "a: b",
    " lead",
    "trail ",
    "x\nexposed_columns: [evil]",
    "quote'd",
    'dq"d',
    "ünï",
    "y" * 300,
]


def test_every_awkward_name_round_trips_exactly() -> None:
    columns = tuple(col(name) for name in TRAPS)
    key_columns = tuple(col(f"k{name}", pk=True) for name in TRAPS)
    text, loaded = draft({"A": [table("s", "t", *columns, *key_columns)]})

    (entry,) = loaded["exposed_columns"]
    assert entry["columns"] == sorted(TRAPS, key=str.casefold)
    for key in ("mode", "exposed_columns", "deny"):
        assert sum(1 for line in text.splitlines() if line.startswith(f"{key}:")) == 1


def test_a_hostile_key_column_cannot_leave_the_comment_block() -> None:
    hostile = "x\nexposed_columns: [evil]\ndeny: [evil]"
    text, loaded = draft({"A": [table("s", "t", col(hostile, pk=True), col("y" * 300, pk=True))]})

    assert loaded["exposed_columns"] == []
    assert loaded["deny"] == []
    for line in text.splitlines():
        assert (
            not line
            or line.startswith("#")
            or line.split(":")[0]
            in {
                "mode",
                "exposed_columns",
                "deny",
            }
        )
    for key in ("mode", "exposed_columns", "deny"):
        assert sum(1 for line in text.splitlines() if line.startswith(f"{key}:")) == 1


def test_names_in_comments_cannot_start_a_new_line() -> None:
    text, _ = draft(
        {
            "db\nexposed_columns: [evil]": [table(None, "t", col("Amount"), col("Extra"))],
            "other": [table(None, "t", col("Amount"))],
        }
    )

    assert "\nexposed_columns: [evil]" not in text
    assert sum(1 for line in text.splitlines() if line.startswith("exposed_columns:")) == 1


def test_the_draft_validates_as_a_pii_config() -> None:
    _, loaded = draft(
        {
            "A": [
                table("dbo", "Orders", col("Id", pk=True), col("Amount"), col("Notes", "string")),
                table("dbo", "Users", col("Id", pk=True), col("Name", "string")),
            ]
        }
    )

    PiiConfig.model_validate(loaded)


def test_an_empty_choice_is_still_a_valid_pii_config() -> None:
    _, loaded = draft({"A": [table(None, "t", col("Name", "string"))]})

    assert loaded == {"mode": "deny-by-default", "exposed_columns": [], "deny": []}
    PiiConfig.model_validate(loaded)


def test_the_output_is_deterministic_for_any_input_order() -> None:
    tables = [
        table("dbo", f"T{index}", col("Id", pk=True), col("Amount"), col("Notes", "string"))
        for index in range(6)
    ]
    first = render_scaffold("alias", catalog({"A": tables, "B": tables}), ENFORCED)
    shuffled = list(reversed(tables))
    random.Random(7).shuffle(shuffled)
    second = render_scaffold("alias", catalog({"B": shuffled, "A": tables[::-1]}), ENFORCED)

    assert first == second


def test_the_header_lists_the_reflected_databases_and_the_scope_of_the_entries() -> None:
    text, _ = draft(
        {"A": [table(None, "t", col("Amount"))], "B": [table(None, "t", col("Amount"))]},
        visible=50,
    )

    assert "# Reflected 2 of 50 databases: A, B." in text
    assert "Entries apply to every database of the alias, including ones not reflected." in text
    assert "A suggestion, not a decision" in text
    assert "# Summary: open 1, deny 0, key 0, token 0" in text


def test_a_long_database_list_is_shortened() -> None:
    databases = {f"db{index:02d}": [table(None, "t", col("Amount"))] for index in range(12)}
    text, _ = draft(databases, visible=12)

    assert "# Reflected all 12 databases: db00, db01, db02, db03, db04, ... (+7 more)." in text
    assert "db11" not in text


def test_only_in_is_shortened_for_many_databases() -> None:
    databases: dict[str, list[ScaffoldTable]] = {
        f"db{index:02d}": [table(None, "t", col("Amount"))] for index in range(12)
    }
    databases["db00"] = [table(None, "t", col("Amount"), col("Extra"))]
    databases["db01"] = [table(None, "t", col("Amount"), col("Extra"))]
    text, _ = draft(databases, visible=12)

    assert "# only in db00, db01: t.Extra" in text


# --- collecting the schema --------------------------------------------------------------------


class _Pool:
    def __init__(self, fail_on: str | None = None) -> None:
        self.fail_on = fail_on
        self.opened: list[str | None] = []
        self.disposed = False

    def get(self, _alias: str, database: str | None = None) -> Any:
        self.opened.append(database)
        failing = self.fail_on is not None and database == self.fail_on
        return _Engine(failing)

    def dispose(self) -> None:
        self.disposed = True


class _Engine:
    def __init__(self, failing: bool) -> None:
        self.failing = failing

    def connect(self) -> Any:
        if self.failing:
            raise _DriverFailure("08001", "Login failed for user 'u' (pwd scaffold-pass-marker)")
        return _Connection()


class _DriverFailure(Exception):
    pass


class _Connection:
    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Extras:
    def __init__(self, names: list[str], fail: bool = False) -> None:
        self.names = names
        self.fail = fail

    def list_databases(self, _connection: object) -> list[str]:
        if self.fail:
            raise _DriverFailure("42000", "scaffold-pass-marker")
        return self.names


def _collect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    *,
    visible: list[str],
    requested: tuple[str, ...] = (),
    pool: _Pool | None = None,
    list_fails: bool = False,
) -> tuple[ScaffoldCatalog, _Pool]:
    import base64

    from sql_safe_mcp import pii_scaffold
    from sql_safe_mcp.config import load_config

    config_path = tmp_path / "scaffold.yaml"
    config_path.write_text(
        """
version: 1
servers:
  clinic:
    engine: mysql
    access_level: all_pii_safe
    connection_url: mysql+pymysql://user:scaffold-pass-marker@host/clinic?ssl_ca=/ca.pem
    pii_key_env: SCAFFOLD_KEY
    pii:
      rules:
        - {database: "*", table: patients, columns: [email]}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("SCAFFOLD_KEY", base64.b64encode(b"k" * 32).decode("ascii"))
    config = load_config(config_path)
    used = pool or _Pool()
    monkeypatch.setattr(pii_scaffold, "EngineRegistry", lambda _config: used)
    monkeypatch.setattr(pii_scaffold, "extras_for", lambda _engine: _Extras(visible, list_fails))
    monkeypatch.setattr(
        pii_scaffold, "_reflect", lambda _connection: [(None, "patients", (col("visits"),))]
    )
    return pii_scaffold.collect_scaffold_catalog(config, "clinic", requested), used


def test_without_database_options_every_visible_database_is_reflected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    result, pool = _collect(monkeypatch, tmp_path, visible=["b", "A", "c"])

    assert list(result.databases) == ["A", "b", "c"]
    assert result.visible == 3
    assert pool.disposed


def test_database_options_pick_the_server_spelling_and_drop_duplicates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    result, _ = _collect(
        monkeypatch,
        tmp_path,
        visible=["Alpha", "beta", "gamma"],
        requested=("alpha", "ALPHA", "beta"),
    )

    assert list(result.databases) == ["Alpha", "beta"]
    assert result.visible == 3


def test_a_database_the_login_cannot_see_is_an_error_naming_only_the_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from sql_safe_mcp.pii_audit import CatalogError

    pool = _Pool()
    with pytest.raises(CatalogError, match=r"database 'x\?y' is not visible"):
        _collect(monkeypatch, tmp_path, visible=["a"], requested=("x\ny",), pool=pool)
    assert pool.disposed


def test_a_listing_failure_is_reported_without_the_driver_message(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from sql_safe_mcp.pii_audit import CatalogError

    with pytest.raises(CatalogError) as raised:
        _collect(monkeypatch, tmp_path, visible=["a"], list_fails=True)
    assert str(raised.value).startswith("cannot list databases: ")
    assert "scaffold-pass-marker" not in str(raised.value)


def test_a_reflection_failure_names_the_database_without_the_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from sql_safe_mcp.pii_audit import CatalogError

    with pytest.raises(CatalogError) as raised:
        _collect(monkeypatch, tmp_path, visible=["a", "b"], pool=_Pool(fail_on="b"))
    assert str(raised.value).startswith("cannot reflect database 'b': ")
    assert "scaffold-pass-marker" not in str(raised.value)


def test_a_long_list_of_protected_columns_is_cut_like_the_other_lists() -> None:
    names = [f"c{i:02d}" for i in range(12)]
    pii = PiiConfig(rules=[PiiRule(database="*", table="t", columns=names)])

    text, _ = draft({"A": [table(None, "t", *(col(name) for name in names))]}, pii)

    assert (
        "# protected by an existing rule: t.c00, t.c01, t.c02, t.c03, t.c04, ... (+7 more)" in text
    )
    assert "t.c11" not in text


# --- decisions the mutation gate must see ------------------------------------------------------


def test_a_schema_scoped_rule_protects_only_that_schema() -> None:
    pii = PiiConfig(rules=[PiiRule(database="*", schema="dbo", table="Orders", columns=["Amount"])])

    _, loaded = draft(
        {
            "A": [
                table("dbo", "Orders", col("Amount"), col("Total")),
                table("hr", "Orders", col("Amount"), col("Total")),
            ]
        },
        pii,
    )

    assert loaded["exposed_columns"] == [
        {"schema": "dbo", "table": "Orders", "columns": ["Total"]},
        {"schema": "hr", "table": "Orders", "columns": ["Amount", "Total"]},
    ]


def test_a_schema_with_a_star_is_not_listed_and_is_named() -> None:
    text, loaded = draft({"A": [table("a*b", "t", col("x"), col("y"))]})

    assert loaded["exposed_columns"] == []
    assert "# not listable: a?b.t (the schema name has a '*')" in text
    assert "token 2" in text


def test_the_summary_counts_every_kind_of_token_once_per_column() -> None:
    pii = PiiConfig(rules=[PiiRule(database="*", schema="dbo", table="t", columns=["prot"])])
    text, _ = draft(
        {
            "A": [
                table(
                    "dbo",
                    "t",
                    col("a_email"),
                    col("b_email2"),
                    col("c_only"),
                    col("d_only"),
                    col("e_X"),
                    col("e_x"),
                    col("f_Y"),
                    col("f_y"),
                    col("prot"),
                )
            ],
            "B": [
                table(
                    "dbo",
                    "t",
                    col("a_email"),
                    col("b_email2"),
                    col("e_X"),
                    col("e_x"),
                    col("f_Y"),
                    col("f_y"),
                    col("prot"),
                )
            ],
        },
        pii,
    )

    assert "# Summary: open 0, deny 0, key 0, token 6, protected 1" in text
    assert "# protected by an existing rule: dbo.t.prot" in text
    assert "# not listable: dbo.t.e_X, dbo.t.e_x, dbo.t.f_Y, dbo.t.f_y" in text
    assert "# only in A: dbo.t.c_only" in text


@pytest.mark.parametrize(
    ("count", "expected"),
    [(5, "d0, d1, d2, d3, d4"), (6, "d0, d1, d2, d3, d4, ... (+1 more)")],
)
def test_a_list_is_cut_only_after_five_names(count: int, expected: str) -> None:
    databases = {f"d{i}": [table(None, "t", col("shared"), col("extra"))] for i in range(count)}
    databases["zz"] = [table(None, "t", col("shared"))]

    text, _ = draft(databases)

    assert f"# only in {expected}: t.extra" in text


def test_the_first_spelling_by_case_folded_order_wins_whatever_the_input_order() -> None:
    first = table("dbo", "users", col("x"))
    second = table("Dbo", "Users", col("x"))

    for order in ([first, second], [second, first]):
        _, loaded = draft({"A": order})
        assert loaded["exposed_columns"] == [{"schema": "Dbo", "table": "Users", "columns": ["x"]}]


def test_a_schema_called_xxxx_is_not_the_missing_schema() -> None:
    _, loaded = draft({"A": [table(None, "t", col("x")), table("xxxx", "t", col("y"))]})

    assert loaded["exposed_columns"] == [
        {"table": "t", "columns": ["x"]},
        {"schema": "xxxx", "table": "t", "columns": ["y"]},
    ]


def test_databases_are_listed_in_case_folded_order() -> None:
    text, _ = draft({"B": [table(None, "t", col("x"))], "a": [table(None, "t", col("x"))]})

    assert "# Reflected all 2 databases: a, B." in text


def test_a_long_name_never_leaves_the_comment_block() -> None:
    long_name = "T" + "x" * 200
    text, _ = draft({"A": [table(None, long_name, col("Id", pk=True), col("OtherId"))]})

    start = text.index("#   - ")
    assert all(line.startswith("#") for line in text[start:].splitlines() if line)
    assert long_name in text


def test_a_skipped_schema_does_not_stop_or_reset_the_count() -> None:
    text, loaded = draft(
        {
            "A": [
                table(None, "a", col("email")),
                table("a*b", "t", col("x"), col("y")),
                table("dbo", "z", col("n")),
            ]
        }
    )

    assert loaded["exposed_columns"] == [{"schema": "dbo", "table": "z", "columns": ["n"]}]
    assert "open 1, deny 0, key 0, token 3" in text


def test_schemas_that_differ_only_by_case_resolve_to_the_same_spelling_in_any_order() -> None:
    lower = table("dbo", "t", col("x"))
    upper = table("Dbo", "t", col("x"))

    for order in ([lower, upper], [upper, lower]):
        _, loaded = draft({"A": order})
        assert loaded["exposed_columns"] == [{"schema": "Dbo", "table": "t", "columns": ["x"]}]


def test_names_that_differ_only_by_case_with_equal_columns_resolve_in_any_order() -> None:
    lower = table("dbo", "users", col("x"))
    upper = table("dbo", "Users", col("x"))

    for order in ([lower, upper], [upper, lower]):
        _, loaded = draft({"A": order})
        assert loaded["exposed_columns"] == [{"schema": "dbo", "table": "Users", "columns": ["x"]}]
