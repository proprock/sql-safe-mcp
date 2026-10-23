"""Hypothesis properties, security-deep profile (thousands of examples; nightly/manual gate).

Run: uv run pytest tests/security -m deep
Reproduce a failure with the printed @reproduce_failure blob or --hypothesis-seed=N.
"""

from __future__ import annotations

import property_checks as checks
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlglot import exp
from support import Spec, specs
from test_properties import ALIAS_NAMES, ALLOWED_KINDS, SEEDS, SQL_FRAGMENTS

pytestmark = pytest.mark.deep
DEEP = settings.get_profile("security-deep")


@settings(DEEP)
@given(st.sampled_from(ALLOWED_KINDS), st.sampled_from(ALLOWED_KINDS))
def test_deep_node_position_is_allowlisted(kind: type[exp.Expr], parent: type[exp.Expr]) -> None:
    checks.check_node_position_is_allowlisted(kind, parent)


@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_valid_specs_are_accepted(spec: Spec, seed: int) -> None:
    checks.check_valid_specs_are_accepted(spec, seed)


@settings(DEEP)
@given(specs(), SEEDS, SEEDS)
def test_deep_formatting_does_not_change_the_decision(spec: Spec, a: int, b: int) -> None:
    checks.check_formatting_does_not_change_the_decision(spec, a, b)


@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_alias_rename_keeps_lineage(spec: Spec, seed: int) -> None:
    checks.check_alias_rename_keeps_lineage(spec, seed)


@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_generated_sql_reparses_and_validates(spec: Spec, seed: int) -> None:
    checks.check_generated_sql_reparses_and_validates(spec, seed)


@settings(DEEP)
@given(specs(), SEEDS)
def test_deep_every_forbidden_mutation_actually_changes_the_query(spec: Spec, seed: int) -> None:
    checks.check_every_forbidden_mutation_changes_the_query(spec, seed)


@settings(DEEP)
@given(specs(), SEEDS, st.integers(0, 10_000))
def test_deep_forbidden_constructs_are_rejected_and_never_executed(
    spec: Spec, seed: int, mutation: int
) -> None:
    checks.check_forbidden_constructs_are_rejected_and_never_executed(spec, seed, mutation)


@settings(DEEP)
@given(st.one_of(st.text(max_size=400), SQL_FRAGMENTS))
def test_deep_only_validated_sql_is_ever_executed(text: str) -> None:
    checks.check_only_validated_sql_is_ever_executed(text)


@settings(DEEP)
@given(st.lists(st.text(alphabet="ÀÉÎÕÜßøæ ", min_size=4, max_size=60), min_size=1, max_size=8))
def test_deep_plaintext_is_never_serialized(values: list[str]) -> None:
    checks.check_plaintext_is_never_serialized(values)


@settings(DEEP)
@given(st.text(max_size=80), ALIAS_NAMES, ALIAS_NAMES)
def test_deep_token_belongs_to_its_alias(value: str, a: str, b: str) -> None:
    checks.check_token_belongs_to_its_alias(value, a, b)


@settings(DEEP)
@given(st.text(max_size=80), st.integers(0, 10_000), st.characters(codec="ascii"))
def test_deep_tampered_token_is_rejected(value: str, position: int, replacement: str) -> None:
    checks.check_tampered_token_is_rejected(value, position, replacement)


@settings(DEEP)
@given(st.one_of(st.text(max_size=600), st.binary(max_size=400).map(lambda b: b.hex())))
def test_deep_arbitrary_token_input_only_raises_the_public_error(text: str) -> None:
    checks.check_arbitrary_token_input_only_raises_the_public_error(text)


@settings(DEEP)
@given(st.text(max_size=120))
def test_deep_sql_looking_values_stay_binds(value: str) -> None:
    checks.check_sql_looking_values_stay_binds(value)
