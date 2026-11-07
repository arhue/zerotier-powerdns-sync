# zerotier-powerdns-sync

Publishes the members of a ZeroTier network as DNS records. It reads each member's
name and assigned IPs from the [ZeroTier Central API](https://docs.zerotier.com/api/central)
and creates A/AAAA records with RFC 2136 dynamic updates signed with TSIG, the same way
Kea DHCP-DDNS does. Works with PowerDNS or any server that accepts RFC 2136 updates.

Only authorized members with a name are used. Names become DNS labels: lowercased,
with anything other than letters, digits and `-` turned into `-`
(`Pixel_9a GrapheneOS` becomes `pixel-9a-grapheneos`).

## Usage

Create an API token at <https://my.zerotier.com/account>, then:

```sh
export ZT_NETWORK_ID=abcdef0123456789
export ZT_API_TOKEN=...            # keep it out of shell history / git

PYTHONPATH=src python -m zt_pdns_sync     # from a checkout
zt-pdns-sync                              # after `pip install .`
```

It prints every authorized member that has a name, with its assigned IPs:

```
docker-3    192.168.169.23, fd12:3456::23
laptop      192.168.169.5, fd12:3456::5
```

## Syncing to DNS

```sh
export DNS_SERVER=2001:db8::53          # authoritative server that accepts updates
export DNS_DOMAIN=zt.example.com        # hostnames go under this; the zone is detected
export TSIG_KEY_NAME=zt-dns-sync
export TSIG_KEY_SECRET=...              # base64
# optional: TSIG_KEY_ALGORITHM (default hmac-sha256), DNS_TTL (default 300)

zt-pdns-sync sync
```

It only sends an update when a record differs from what the server returns, so running
it on a timer doesn't bump the zone serial needlessly. Records for members that are
removed or renamed are not deleted yet.

### PowerDNS setup

```sh
pdnsutil generate-tsig-key zt-dns-sync hmac-sha256
pdnsutil set-meta example.com TSIG-ALLOW-DNSUPDATE zt-dns-sync   # keep any existing keys
```

and in `pdns.conf`: `dnsupdate=yes`, `allow-dnsupdate-from=<where this runs>`, and
optionally `dnsupdate-require-tsig=yes`.

## License

MIT
