from __future__ import annotations

import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

from sql_safe_mcp.config import load_config
from sql_safe_mcp.errors import DomainError
from sql_safe_mcp.mcp_server import create_server
from sql_safe_mcp.pii_audit import collect_catalog, verify_pii_rules


def _positive_int(value: str) -> int:
    count = int(value)
    if count < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return count


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the sql-safe-mcp stdio server.")
    parser.add_argument(
        "--config",
        type=Path,
        default=os.environ.get("SQL_SAFE_MCP_CONFIG", "sql-safe-mcp.yaml"),
        help="YAML configuration path (default: SQL_SAFE_MCP_CONFIG or sql-safe-mcp.yaml)",
    )
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration and secrets without connecting to databases.",
    )
    actions.add_argument(
        "--gen-pii-key",
        nargs="?",
        type=_positive_int,
        const=1,
        metavar="N",
        help="Print N base64-encoded 32-byte PII keys (default: 1) and exit.",
    )
    actions.add_argument(
        "--verify-pii-rules",
        action="store_true",
        help="Connect to each all_pii_safe alias and report PII rules that match nothing.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="With --verify-pii-rules, exit 2 when any rule matches nothing.",
    )
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    if args.strict and not args.verify_pii_rules:
        parser.error("--strict requires --verify-pii-rules")
    if args.gen_pii_key is not None:
        for _ in range(args.gen_pii_key):
            print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
        return
    try:
        config = load_config(args.config)
    except DomainError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None
    if args.check_config:
        print(f"Configuration valid: {len(config.servers)} server alias(es).")
        return
    if args.verify_pii_rules:
        report = verify_pii_rules(config, collect_catalog)
        print("\n".join(report.lines), file=sys.stderr)
        if report.errors or (args.strict and report.unmatched_rules):
            raise SystemExit(2)
        return
    create_server(config).run("stdio")


if __name__ == "__main__":
    main()
