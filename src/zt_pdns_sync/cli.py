"""Print the name and IP addresses of each named, authorized ZeroTier member.

Configuration (environment):
  ZT_NETWORK_ID  ZeroTier network ID
  ZT_API_TOKEN   ZeroTier Central API token
"""

from __future__ import annotations

import os
import sys

from .zerotier import ZeroTierClient, ZeroTierError


def main() -> int:
    network = os.environ.get("ZT_NETWORK_ID")
    token = os.environ.get("ZT_API_TOKEN")
    if not network or not token:
        print("error: set ZT_NETWORK_ID and ZT_API_TOKEN", file=sys.stderr)
        return 2

    try:
        members = ZeroTierClient(token).members(network)
    except ZeroTierError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    members = sorted((m for m in members if m.authorized and m.name), key=lambda m: m.name.lower())
    width = max((len(m.name) for m in members), default=0)
    for m in members:
        print(f"{m.name.ljust(width)}  {', '.join(m.ips) or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
