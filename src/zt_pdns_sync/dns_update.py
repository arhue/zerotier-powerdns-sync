"""Publish A/AAAA records with RFC 2136 dynamic updates signed with TSIG (as Kea DHCP-DDNS does)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.tsigkeyring
import dns.update


class DNSUpdateError(Exception):
    pass


def hostname(name: str) -> str:
    """Turn a ZeroTier member name into a DNS label: "Pixel_9a GrapheneOS" -> "pixel-9a-grapheneos"."""
    return re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")[:63]


@dataclass
class Change:
    fqdn: str
    rdtype: str
    old: set[str]
    new: set[str]


class DNSUpdater:
    def __init__(self, server: str, domain: str, key_name: str, key_secret: str,
                 key_algorithm: str = "hmac-sha256", ttl: int = 300, port: int = 53,
                 timeout: float = 10):
        self.server = server
        self.port = port
        self.timeout = timeout
        self.domain = dns.name.from_text(domain)
        self.ttl = ttl
        self.keyring = dns.tsigkeyring.from_text({key_name: (key_algorithm, key_secret)})
        self.key_name = dns.name.from_text(key_name)
        self.zone = self._find_zone()

    def _query(self, qname: dns.name.Name, rdtype: str) -> dns.message.Message:
        q = dns.message.make_query(qname, rdtype)
        try:
            return dns.query.udp(q, self.server, port=self.port, timeout=self.timeout)
        except Exception as e:
            raise DNSUpdateError(f"cannot query {self.server}: {e}") from e

    def _find_zone(self) -> dns.name.Name:
        """The zone apex that contains the domain (e.g. zt.priolkar.com is inside priolkar.com)."""
        name = self.domain
        while True:
            resp = self._query(name, "SOA")
            if any(rr.rdtype == dns.rdatatype.SOA and rr.name == name for rr in resp.answer):
                return name
            if name == dns.name.root:
                raise DNSUpdateError(f"{self.server} is not authoritative for {self.domain}")
            name = name.parent()

    def current(self, fqdn: dns.name.Name, rdtype: str) -> set[str]:
        resp = self._query(fqdn, rdtype)
        return {rd.to_text() for rr in resp.answer if rr.rdtype == dns.rdatatype.from_text(rdtype)
                for rd in rr}

    def plan(self, members) -> list[Change]:
        """Compare the records each named member should have with what the server has now.

        Authorized members get A/AAAA records for their assigned IPs; unauthorized members
        get theirs removed. If an authorized and an unauthorized member map to the same
        hostname, the authorized one wins.
        """
        desired: dict[str, set] = {}
        for m in members:
            label = hostname(m.name)
            if not label:
                continue
            ips = {ipaddress.ip_address(ip) for ip in m.ips} if m.authorized else set()
            desired.setdefault(label, set()).update(ips)

        changes = []
        for label, ips in sorted(desired.items()):
            fqdn = dns.name.from_text(label, self.domain)
            for rdtype, version in (("A", 4), ("AAAA", 6)):
                new = {str(ip) for ip in ips if ip.version == version}
                old = self.current(fqdn, rdtype)
                if new != old:
                    changes.append(Change(fqdn.to_text(), rdtype, old, new))
        return changes

    def apply(self, changes: list[Change]) -> None:
        if not changes:
            return
        update = dns.update.UpdateMessage(self.zone, keyring=self.keyring, keyname=self.key_name)
        for c in changes:
            name = dns.name.from_text(c.fqdn)
            if c.new:
                update.replace(name, self.ttl, c.rdtype, *sorted(c.new))
            else:
                update.delete(name, c.rdtype)
        try:
            resp = dns.query.tcp(update, self.server, port=self.port, timeout=self.timeout)
        except Exception as e:
            raise DNSUpdateError(f"update to {self.server} failed: {e}") from e
        if resp.rcode() != dns.rcode.NOERROR:
            raise DNSUpdateError(
                f"server refused the update: {dns.rcode.to_text(resp.rcode())} "
                "(check the TSIG key, TSIG-ALLOW-DNSUPDATE on the zone, and allow-dnsupdate-from)"
            )
