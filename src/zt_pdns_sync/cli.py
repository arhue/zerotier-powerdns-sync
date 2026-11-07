"""List named, authorized ZeroTier members, or keep their DNS records in sync.

  zt-pdns-sync          print name and IPs of each authorized member
  zt-pdns-sync sync     run forever: publish A/AAAA records for authorized members and
                        remove them for unauthorized or renamed ones (RFC 2136 + TSIG)

Configuration (environment):
  ZT_NETWORK_ID         ZeroTier network ID
  ZT_API_TOKEN          ZeroTier Central API token
  DNS_SERVER            authoritative server IP to send updates to (sync only)
  DNS_DOMAIN            domain the hostnames go under, e.g. zt.example.com (sync only)
  TSIG_KEY_NAME         TSIG key name (sync only)
  TSIG_KEY_SECRET       TSIG key secret, base64 (sync only)
  TSIG_KEY_ALGORITHM    default hmac-sha256
  DNS_TTL               record TTL in seconds, default 300
  SYNC_INTERVAL         seconds between syncs, default 60
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time

from .zerotier import ZeroTierClient, ZeroTierError


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        print(f"error: {name} is not set", file=sys.stderr)
        sys.exit(2)
    return value


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


def list_members(client: ZeroTierClient, network: str) -> int:
    try:
        members = client.members(network)
    except ZeroTierError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    members = sorted((m for m in members if m.authorized and m.name), key=lambda m: m.name.lower())
    width = max((len(m.name) for m in members), default=0)
    for m in members:
        print(f"{m.name.ljust(width)}  {', '.join(m.ips) or '-'}")
    return 0


def sync_forever(client: ZeroTierClient, network: str) -> int:
    from .dns_update import DNSUpdateError, DNSUpdater

    settings = dict(
        server=env("DNS_SERVER"),
        domain=env("DNS_DOMAIN"),
        key_name=env("TSIG_KEY_NAME"),
        key_secret=env("TSIG_KEY_SECRET"),
        key_algorithm=env("TSIG_KEY_ALGORITHM", "hmac-sha256"),
        ttl=int(env("DNS_TTL", "300")),
    )
    interval = int(env("SYNC_INTERVAL", "60"))

    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())

    log(f"syncing network {network} to {settings['domain']} via {settings['server']} "
        f"every {interval}s")
    updater = None
    while not stop.is_set():
        try:
            if updater is None:  # retried each round until the server is reachable
                updater = DNSUpdater(**settings)
            members = client.members(network)
            changes = updater.plan(members)
            for c in changes:
                old = ", ".join(sorted(c.old)) or "-"
                new = ", ".join(sorted(c.new)) or "(removed)"
                log(f"{c.fqdn} {c.rdtype}: {old} -> {new}")
            updater.apply(changes)
            if changes:
                log(f"{len(changes)} change(s) applied to zone {updater.zone}")
        except (ZeroTierError, DNSUpdateError) as e:
            log(f"error: {e}")
        stop.wait(interval)
    log("stopped")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv not in ([], ["sync"]):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    client = ZeroTierClient(env("ZT_API_TOKEN"))
    network = env("ZT_NETWORK_ID")
    return sync_forever(client, network) if argv else list_members(client, network)


if __name__ == "__main__":
    sys.exit(main())
