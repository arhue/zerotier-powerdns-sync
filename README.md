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

PYTHONPATH=src python -m zt_pdns_sync     # from a checkout
zt-pdns-sync                              # after `pip install .`
```

It prints every authorized member that has a name, with its assigned IPs:

```
docker-3    192.168.169.23, fd12:3456::23
laptop      192.168.169.5, fd12:3456::5
```

## License

MIT
