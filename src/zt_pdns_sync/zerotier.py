"""Minimal client for the ZeroTier Central API (https://docs.zerotier.com/api/central)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

API_URL = "https://api.zerotier.com/api/v1"


class ZeroTierError(Exception):
    pass


@dataclass(frozen=True)
class Member:
    node_id: str
    name: str
    authorized: bool
    ips: tuple[str, ...]

    @classmethod
    def from_api(cls, data: dict) -> "Member":
        config = data.get("config") or {}
        return cls(
            node_id=data.get("nodeId") or config.get("address", ""),
            name=(data.get("name") or "").strip(),
            authorized=bool(config.get("authorized")),
            ips=tuple(config.get("ipAssignments") or ()),
        )


class ZeroTierClient:
    def __init__(self, token: str, api_url: str = API_URL, timeout: float = 15):
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def _get(self, path: str):
        req = urllib.request.Request(
            f"{self.api_url}{path}",
            headers={"Authorization": f"token {self.token}", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise ZeroTierError("ZeroTier API rejected the token (HTTP %d)" % e.code) from e
            if e.code == 404:
                raise ZeroTierError(f"Not found: {path} (wrong network ID?)") from e
            raise ZeroTierError(f"ZeroTier API error: HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise ZeroTierError(f"Cannot reach ZeroTier API: {e.reason}") from e

    def members(self, network_id: str) -> list[Member]:
        return [Member.from_api(m) for m in self._get(f"/network/{network_id}/member")]
