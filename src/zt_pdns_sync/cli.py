"""List named, authorized ZeroTier members, or sync them into DNS.

  zt-pdns-sync          print name and IPs of each member
  zt-pdns-sync sync     create/update their A and AAAA records (RFC 2136 + TSIG)

Configuration (environment):
  ZT_NETWORK_ID         ZeroTier network ID
  ZT_API_TOKEN          ZeroTier Central API token
  DNS_SERVER            authoritative server IP to send updates to (sync only)
  DNS_DOMAIN            domain the hostnames go under, e.g. zt.example.com (sync only)
  TSIG_KEY_NAME         TSIG key name (sync only)
  TSIG_KEY_SECRET       TSIG key secret, base64 (sync only)
  TSIG_KEY_ALGORITHM    default hmac-sha256
  DNS_TTL               default 300
"""

from __future__ import annotations

import os
import sys

from .zerotier import ZeroTierClient, ZeroTierError


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        print(f"error: {name} is not set", file=sys.stderr)
        sys.exit(2)
    return value


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv not in ([], ["sync"]):
        print(__doc__.strip(), file=sys.stderr)
        return 2

    try:
        members = ZeroTierClient(env("ZT_API_TOKEN")).members(env("ZT_NETWORK_ID"))
    except ZeroTierError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    members = sorted((m for m in members if m.authorized and m.name), key=lambda m: m.name.lower())

    if not argv:
        width = max((len(m.name) for m in members), default=0)
        for m in members:
            print(f"{m.name.ljust(width)}  {', '.join(m.ips) or '-'}")
        return 0

    from .dns_update import DNSUpdateError, DNSUpdater

    try:
        updater = DNSUpdater(
            server=env("DNS_SERVER"),
            domain=env("DNS_DOMAIN"),
            key_name=env("TSIG_KEY_NAME"),
            key_secret=env("TSIG_KEY_SECRET"),
            key_algorithm=env("TSIG_KEY_ALGORITHM", "hmac-sha256"),
            ttl=int(env("DNS_TTL", "300")),
        )
        changes = updater.plan(members)
        for c in changes:
            old = ", ".join(sorted(c.old)) or "-"
            new = ", ".join(sorted(c.new)) or "(delete)"
            print(f"{c.fqdn} {c.rdtype}: {old} -> {new}")
        updater.apply(changes)
    except DNSUpdateError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{len(changes)} change(s) applied to zone {updater.zone}" if changes else "up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
