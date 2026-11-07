# zerotier-powerdns-sync

Lists the members of a ZeroTier network (name + assigned IP addresses) using the
[ZeroTier Central API](https://docs.zerotier.com/api/central). Next step: publish
those as DNS records to PowerDNS via RFC 2136 dynamic updates (TSIG), the same way
Kea DHCP-DDNS does.

## Usage

Create an API token at <https://my.zerotier.com/account>, then:

```sh
export ZT_NETWORK_ID=abcdef0123456789
export ZT_API_TOKEN=...            # keep it out of shell history / git

python -m zt_pdns_sync             # authorized members
python -m zt_pdns_sync --all       # include unauthorized members
python -m zt_pdns_sync --json
```

Or install it: `pip install .` and run `zt-pdns-sync`.

Run from a checkout without installing: `PYTHONPATH=src python -m zt_pdns_sync`.

Example output:

```
NAME       NODE ID     AUTH  IP ADDRESSES
docker-1   a1b2c3d4e5  yes   192.168.169.21, fd12:3456::1
laptop     0f1e2d3c4b  yes   192.168.169.50
```

## License

MIT
