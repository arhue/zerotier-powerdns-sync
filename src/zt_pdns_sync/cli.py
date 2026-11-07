"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .zerotier import ZeroTierClient, ZeroTierError


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="zt-pdns-sync",
        description="List ZeroTier network members with their names and IP addresses.",
    )
    p.add_argument(
        "--network",
        default=os.environ.get("ZT_NETWORK_ID"),
        help="ZeroTier network ID (env: ZT_NETWORK_ID)",
    )
    p.add_argument(
        "--token",
        default=os.environ.get("ZT_API_TOKEN"),
        help="ZeroTier Central API token (env: ZT_API_TOKEN; prefer the env var so the "
        "token stays out of shell history)",
    )
    p.add_argument("--all", action="store_true", help="include unauthorized members")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = p.parse_args(argv)
    if not args.network or not args.token:
        p.error("network ID and API token are required (ZT_NETWORK_ID / ZT_API_TOKEN)")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        members = ZeroTierClient(args.token).members(args.network)
    except ZeroTierError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if not args.all:
        members = [m for m in members if m.authorized]
    members.sort(key=lambda m: (m.name.lower() or "~", m.node_id))

    if args.json:
        print(json.dumps([m.__dict__ | {"ips": list(m.ips)} for m in members], indent=2))
        return 0

    rows = [("NAME", "NODE ID", "AUTH", "IP ADDRESSES")] + [
        (m.name or "(unnamed)", m.node_id, "yes" if m.authorized else "no", ", ".join(m.ips) or "-")
        for m in members
    ]
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)) + "  " + r[3])
    return 0


if __name__ == "__main__":
    sys.exit(main())
