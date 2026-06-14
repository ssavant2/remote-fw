#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sophos_api import SophosAPIError, SophosFirewallClient  # noqa: E402


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def parse_bool(value: str | None, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def rule_names() -> list[str]:
    raw = os.environ.get("RULE_NAMES", "")
    return sorted([name.strip() for name in raw.split(",") if name.strip()], key=str.casefold)


def rule_groups() -> dict[str, str]:
    raw = os.environ.get("RULE_GROUPS", "")
    groups = {}
    for item in raw.replace("\n", ";").split(";"):
        item = item.strip()
        if not item:
            continue
        separator = "|" if "|" in item else "="
        if separator not in item:
            continue
        rule_name, group_name = item.split(separator, 1)
        if rule_name.strip() and group_name.strip():
            groups[rule_name.strip()] = group_name.strip()
    return groups


def client() -> SophosFirewallClient:
    return SophosFirewallClient(
        host=os.environ.get("SFOS_HOST", ""),
        port=os.environ.get("SFOS_PORT", "4444"),
        username=os.environ.get("SFOS_USERNAME", ""),
        password=os.environ.get("SFOS_PASSWORD", ""),
        verify_tls=parse_bool(os.environ.get("SFOS_VERIFY_TLS"), default=True),
        timeout=int(os.environ.get("SFOS_TIMEOUT", "30")),
    )


def show_status(selected_rule: str | None) -> int:
    fw = client()
    names = [selected_rule] if selected_rule else rule_names()
    dynamic_groups = fw.get_rule_group_memberships(names)
    fallback_groups = rule_groups()
    for name in names:
        status = fw.get_rule_status(name)
        group = dynamic_groups.get(name) or fallback_groups.get(name)
        group_text = f", group={group}" if group else ""
        source_zones = ", ".join(status.source_zones)
        source_networks = ", ".join(status.source_networks)
        print(
            f"{status.name}: {status.status} "
            f"(sources={source_zones}; networks={source_networks}{group_text})"
        )
    return 0


def toggle_test(selected_rule: str) -> int:
    fw = client()
    group_name = rule_groups().get(selected_rule)
    original = fw.get_rule_status(selected_rule)
    target = "Disable" if original.enabled else "Enable"
    print(f"original_status={original.status}")
    print(f"test_status={target}")
    try:
        changed = fw.set_rule_status(selected_rule, target, group_name=group_name)
        print(f"after_test_status={changed.status}")
    finally:
        restored = fw.set_rule_status(selected_rule, original.status, group_name=group_name)
        print(f"restored_status={restored.status}")
    if group_name:
        print(f"group_preserved={fw.rule_is_in_group(selected_rule, group_name)}")
    return 0


def repair_group(selected_rule: str, group_name: str) -> int:
    fw = client()
    changed = fw.ensure_rule_in_group(selected_rule, group_name)
    print(f"rule={selected_rule}")
    print(f"group={group_name}")
    print(f"changed={changed}")
    print(f"in_group={fw.rule_is_in_group(selected_rule, group_name)}")
    return 0


def main() -> int:
    load_env(ROOT / ".env")
    parser = argparse.ArgumentParser(description="Test Sophos Firewall XML API access.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status", help="Read configured rule statuses.")
    status_parser.add_argument("--rule", help="Read one rule instead of RULE_NAMES.")

    toggle_parser = subparsers.add_parser("toggle-test", help="Toggle a rule and restore it.")
    toggle_parser.add_argument("--rule", required=True, help="Rule name to test.")

    repair_parser = subparsers.add_parser("repair-group", help="Ensure a rule is in a rule group.")
    repair_parser.add_argument("--rule", required=True, help="Rule name to place in the group.")
    repair_parser.add_argument("--group", required=True, help="Rule group name.")

    args = parser.parse_args()
    try:
        if args.command == "status":
            return show_status(args.rule)
        if args.command == "toggle-test":
            return toggle_test(args.rule)
        if args.command == "repair-group":
            return repair_group(args.rule, args.group)
    except SophosAPIError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
