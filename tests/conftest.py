from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

# configure_logging sets these process-wide; a test that builds the server with a quiet level
# would otherwise silence INFO records, such as the audit trail, in every later test.
_PINNED_LOGGERS = ("", "sql_safe_mcp", "sql_safe_mcp.audit", "sqlalchemy")


@pytest.fixture(autouse=True)
def _restore_logger_levels() -> Iterator[None]:
    saved = {name: logging.getLogger(name).level for name in _PINNED_LOGGERS}
    yield
    for name, level in saved.items():
        logging.getLogger(name).setLevel(level)
