"""Hypothesis properties on the mysql dialect: security-fast, and security-deep under -m deep."""

from __future__ import annotations

import property_checks_mysql as checks
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from support import Spec, specs
from test_properties import QUOTED_NAMES, SEEDS, SQL_FRAGMENTS

MYSQL_FRAGMENTS = st.one_of(
    SQL_FRAGMENTS,
    st.lists(
        st.sampled_from(
            [
                "`",
                "``",
                "LIMIT",
                "OFFSET",
                "#",
                "-- ",
                "/*!",
                "@@",
                "\\",
                "%",
                "%s",
                "mysql",
                "app",
                ".",
            ]
        ),
        max_size=20,
    ).map(" ".join),
)
INJECTION_VALUES = st.one_of(
    st.text(max_size=60),
    st.sampled_from(["x'; DROP TABLE Canary;--", "' OR '1'='1", "\\' OR 1=1 -- ", "100%", "%s"]),
)
DEEP = settings.get_profile("security-deep")


@given(specs(), SEEDS)
def test_mysql_valid_specs_are_accepted(spec: Spec, seed: int) -> None:
    checks.check_valid_specs_are_accepted(spec, seed)


@given(specs(), SEEDS, SEEDS)
def test_mysql_formatting_does_not_change_the_decision(spec: Spec, a: int, b: int) -> None:
    checks.check_formatting_does_not_change_the_decision(spec, a, b)


@given(specs(), SEEDS)
def test_mysql_alias_rename_keeps_lineage(spec: Spec, seed: int) -> None:
    checks.check_alias_rename_keeps_lineage(spec, seed)


@given(specs(), SEEDS)
def test_mysql_generated_sql_reparses_and_validates(spec: Spec, seed: int) -> None:
    checks.check_generated_sql_reparses_and_validates(spec, seed)


@given(specs(), SEEDS)
def test_mysql_every_forbidden_mutation_actually_changes_the_query(spec: Spec, seed: int) -> None:
    checks.check_every_forbidden_mutation_changes_the_query(spec, seed)


@given(specs(), SEEDS, st.integers(0, 10_000))
def test_mysql_forbidden_constructs_are_rejected_and_never_executed(
    spec: Spec, seed: int, mutation: int
) -> None:
    checks.check_forbidden_constructs_are_rejected_and_never_executed(spec, seed, mutation)


@given(st.one_of(st.text(max_size=200), MYSQL_FRAGMENTS))
def test_mysql_only_validated_sql_is_ever_executed(text: str) -> None:
    checks.check_only_validated_sql_is_ever_executed(text)


@given(INJECTION_VALUES)
def test_mysql_sql_looking_values_stay_binds(value: str) -> None:
    checks.check_sql_looking_values_stay_binds(value)


@given(specs(), SEEDS)
def test_mysql_generated_sql_is_a_fixpoint(spec: Spec, seed: int) -> None:
    checks.check_generated_sql_is_a_fixpoint(spec, seed)


@given(QUOTED_NAMES, QUOTED_NAMES)
def test_mysql_quoted_aliases_round_trip(column_alias: str, table_alias: str) -> None:
    checks.check_quoted_aliases_round_trip(column_alias, table_alias)


@given(specs(), SEEDS)
def test_dialects_agree_on_lineage(spec: Spec, seed: int) -> None:
    checks.check_dialects_agree_on_lineage(spec, seed)


@given(specs(), SEEDS, st.integers(0, 10_000))
def test_dialects_reject_for_the_same_reason(spec: Spec, seed: int, mutation: int) -> None:
    checks.check_dialects_reject_for_the_same_reason(spec, seed, mutation)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_mysql_generated_sql_is_a_fixpoint(spec: Spec, seed: int) -> None:
    checks.check_generated_sql_is_a_fixpoint(spec, seed)


@pytest.mark.deep
@settings(DEEP)
@given(QUOTED_NAMES, QUOTED_NAMES)
def test_deep_mysql_quoted_aliases_round_trip(column_alias: str, table_alias: str) -> None:
    checks.check_quoted_aliases_round_trip(column_alias, table_alias)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_dialects_agree_on_lineage(spec: Spec, seed: int) -> None:
    checks.check_dialects_agree_on_lineage(spec, seed)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS, st.integers(0, 10_000))
def test_deep_dialects_reject_for_the_same_reason(spec: Spec, seed: int, mutation: int) -> None:
    checks.check_dialects_reject_for_the_same_reason(spec, seed, mutation)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_mysql_valid_specs_are_accepted(spec: Spec, seed: int) -> None:
    checks.check_valid_specs_are_accepted(spec, seed)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS, SEEDS)
def test_deep_mysql_formatting_does_not_change_the_decision(spec: Spec, a: int, b: int) -> None:
    checks.check_formatting_does_not_change_the_decision(spec, a, b)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_mysql_alias_rename_keeps_lineage(spec: Spec, seed: int) -> None:
    checks.check_alias_rename_keeps_lineage(spec, seed)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_mysql_generated_sql_reparses_and_validates(spec: Spec, seed: int) -> None:
    checks.check_generated_sql_reparses_and_validates(spec, seed)


@pytest.mark.deep
@settings(DEEP)
@given(specs(), SEEDS, st.integers(0, 10_000))
def test_deep_mysql_forbidden_constructs_are_rejected_and_never_executed(
    spec: Spec, seed: int, mutation: int
) -> None:
    checks.check_forbidden_constructs_are_rejected_and_never_executed(spec, seed, mutation)


@pytest.mark.deep
@settings(DEEP)
@given(st.one_of(st.text(max_size=400), MYSQL_FRAGMENTS))
def test_deep_mysql_only_validated_sql_is_ever_executed(text: str) -> None:
    checks.check_only_validated_sql_is_ever_executed(text)


@pytest.mark.deep
@settings(DEEP)
@given(INJECTION_VALUES)
def test_deep_mysql_sql_looking_values_stay_binds(value: str) -> None:
    checks.check_sql_looking_values_stay_binds(value)
