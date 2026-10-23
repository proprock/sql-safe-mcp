"""Loads the adversarial corpus and expands its templates for a given alias and key set."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from sql_safe_mcp.security.tokens import PREFIX, TokenCodec

CORPUS = Path(__file__).parent / "corpus"
MYSQL_CORPUS = Path(__file__).parent / "corpus_mysql"
TEMPLATE = re.compile(r"\{\{(\w+)(?::(.*?))?\}\}")


@dataclass(frozen=True, slots=True)
class TokenSources:
    """Codecs used to mint the token templates: the alias under test and foreign ones."""

    own: TokenCodec
    foreign: TokenCodec
    own_alias_other_key: TokenCodec


def load_cases(directory: Path = CORPUS) -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []
    for path in sorted(directory.glob("*.yaml")):
        for case in yaml.safe_load(path.read_text(encoding="utf-8")):
            cases.append((f"{path.stem}::{case['name']}", case))
    return cases


def _std_alphabet_token(own: TokenCodec) -> str:
    for _ in range(500):
        token = own.encrypt("value")
        body = token.removeprefix(PREFIX)
        if "-" in body or "_" in body:
            return PREFIX + body.replace("-", "+").replace("_", "/")
    raise AssertionError("could not build a token with a url-safe character")


def _flipped(token: str) -> str:
    middle = len(PREFIX) + (len(token) - len(PREFIX)) // 2
    replacement = "A" if token[middle] != "A" else "B"
    return token[:middle] + replacement + token[middle + 1 :]


def _expand(name: str, arg: str | None, tokens: TokenSources) -> str:
    own = tokens.own.encrypt("value")
    if name == "TOKEN_OWN":
        return own
    if name == "TOKEN_OWN_INT":
        return tokens.own.encrypt(1)
    if name == "TOKEN_OTHER":
        return tokens.foreign.encrypt("value")
    if name == "TOKEN_OTHER_KEY_SAME_ALIAS":
        return tokens.own_alias_other_key.encrypt("value")
    if name == "TOKEN_BODY":
        return own.removeprefix(PREFIX)
    if name == "TOKEN_TRUNCATED":
        return own[:-8]
    if name == "TOKEN_FLIPPED":
        return _flipped(own)
    if name == "TOKEN_STD_ALPHABET":
        return _std_alphabet_token(tokens.own)
    assert arg is not None, name
    if name == "PAD":
        return " " * int(arg)
    text, _, count = arg.rpartition(":")
    if name in {"PAD_CHAR", "REPEAT"}:
        return text * int(count)
    if name == "IN_LIST":
        return ", ".join(str(i) for i in range(int(arg)))
    if name == "NEST":
        depth = int(arg)
        return "(" * depth + "1" + ")" * depth
    if name == "JOINS":
        return "".join(f" JOIN Orders o{i} ON o{i}.Id = u.Id" for i in range(int(arg)))
    raise AssertionError(f"unknown corpus template {name}")


def expand(sql: str, tokens: TokenSources) -> str:
    return TEMPLATE.sub(lambda match: _expand(match.group(1), match.group(2), tokens), sql)
