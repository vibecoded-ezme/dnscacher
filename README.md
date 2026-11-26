# dnscacher

A small caching DNS forwarder written in Rust.  It serves ordinary DNS over UDP
and TCP as well as DNS over TLS (DoT) and DNS over HTTPS (DoH), forwards cache
misses to plain DNS, DoT or DoH upstreams, and persists its cache across
restarts.

## Features

- UDP and TCP server on any number of IPv4/IPv6 addresses.
- Optional DoT (RFC 7858) and DoH (RFC 8484) listeners that share the cache,
  hosts files, rewrite rules and upstream selection.
- Plain DNS upstreams (UDP with automatic TCP retry on truncation), DoT via
  rustls, and DoH (RFC 8484 POST), with per-table transport ordering.
- Per-domain upstream routing, including subdomains.
- Fixed-lifetime positive and negative caching with TTL adjustment on every hit.
- Persistent cache snapshots and live purging by domain or in full.
- `/etc/hosts` records, reverse (`PTR`) lookups, deny lists, and policy
  rewriting of upstream `0.0.0.0`/`::` answers.
- AdGuard-style `$dnsrewrite` rules for CNAME redirects, address overrides and
  response-code overrides.
- DNSSEC modes: `off`, `allow`, and strict `enforce`.
- EDNS(0) with a 1232-byte upstream payload and UDP truncation for plain clients.
- Query/response matching to reject spoofed or mismatched upstream answers.
- systemd, OpenRC, dinit, runit and s6 service definitions, plus packages for
  Arch Linux, Alpine, Debian/Ubuntu and Fedora/CentOS/RHEL.

## Quick start

```sh
cargo build --release
sudo ./target/release/dnscacher --config example-config.toml
dog example.com @127.0.0.1
```

Port 53 needs root or `CAP_NET_BIND_SERVICE`.  For an unprivileged test on port
5353:

```sh
cargo run -- --config example-config.toml --port 5353
dog example.com @127.0.0.1:5353
```

Copy `example-config.toml` to `/etc/dnscacher.toml` for a system-wide setup.

## Documentation

| Document | Contents |
|----------|----------|
| [doc/build.md](doc/build.md) | building, static musl, checks, CLI options, cache purging |
| [doc/dot-doh.md](doc/dot-doh.md) | DoT/DoH listeners, TLS certificates, client examples |
| [doc/distros.md](doc/distros.md) | systemd, OpenRC, dinit, runit and s6 services; distro packages |
| [example-config.toml](example-config.toml) | complete annotated configuration |

## Configuration

See `example-config.toml` for a complete file.

### Server and cache

```toml
[cache]
ttl = 86_400   # fixed seconds for a positive answer (overrides upstream TTL)
nx = 3_600     # fixed seconds for NXDOMAIN / NODATA (overrides SOA MINIMUM)
persistent = '/var/tmp/dnscacher.cache'
temporary = '/tmp/dnscacher.cache'

[server]
address = [ "127.0.0.1", "::1" ]
port = 53
control = "/run/dnscacher/control.sock" # optional; enables live cache purging

# Optional DoT and DoH listeners are configured as [server.dot] and
# [server.doh]; see doc/dot-doh.md.

[dns]
priority = "order" # order, round-robin, random, all
dnssec = "allow"   # off, allow, enforce
hosts = [ '/etc/hosts', '/etc/hosts.deny' ]
rules = [ '/etc/dnscacher.rules' ] # optional AdGuard-style $dnsrewrite rules
deny = "nx"        # nx/nxdomain, zero, loopback/loop, ip, or { ip = { ... } }
timeout = 5        # optional, seconds per upstream attempt
```

- `persistent` is loaded at startup, written every five minutes and on clean
  shutdown.  `temporary` is written every 15 seconds and removed on clean
  shutdown; it exists so a crash does not throw the cache away.  Both are
  postcard-encoded snapshots and may be omitted.
- `control` is a Unix socket (created with mode `0600`) that accepts purge
  commands from the same binary.  See [Purging the cache](doc/build.md#purging-the-cache).
- `cache.ttl` and `cache.nx` are fixed lifetimes: a positive answer is cached
  for `ttl` seconds and a negative one for `nx` seconds, regardless of the TTL
  returned by the upstream.  Stored record TTLs are rewritten to that value and
  count down from it, so clients see the override.  This intentionally lets a
  5-minute upstream TTL be served for 24 hours; choose values accordingly.
  Responses containing DNSSEC signatures keep an upstream-derived TTL (still
  capped by `ttl`/`nx`) so signatures are not served past their validity.
  TTL 0 answers (and negatives whose SOA `MINIMUM` is 0) are still not cached,
  and neither are SERVFAIL/REFUSED responses or truncated answers.

### Upstreams

Each numbered table is a group of endpoints.  A group can contain several
transports; every produced endpoint participates in the priority strategy.

```toml
[dns.1]
ipv4 = [ "95.217.77.181" ]
domains = [ "nintendowifi.net" ]

[dns.2.ipv4]
addresses = [ "1.1.1.1", "1.0.0.1" ]
port = 53

[dns.2.ipv6]
addresses = [ "2606:4700:4700::1111" ]

[dns.2.dot]
host = "cloudflare-dns.com"  # "host:853" also works
port = 853

[dns.2.doh]
url = "https://cloudflare-dns.com/dns-query"
port = 443

# Optional: order the transports of this table.  Default is
# [ "dot", "doh", "ipv6", "ipv4" ]; unlisted transports are appended.
order = [ "dot", "doh", "ipv6", "ipv4" ]
```

The simple forms are also accepted:

```toml
ipv4 = [ "8.8.8.8" ]
ipv6 = [ "2001:4860:4860::8888" ]
dot = "dns.google"                    # port 853
doh = "https://dns.google/dns-query"  # port 443
```

For a non-default port, either use the nested table shown above or an inline
table:

```toml
ipv4 = { addresses = [ "8.8.8.8" ], port = 5353 }
dot = { host = "dns.google", port = 8853 }
doh = { url = "https://dns.google/dns-query", port = 8443 }
```

A table-level `port = 53` provides the default for every transport in that
table, including DoT and DoH.  Set the port on the individual transport when
they differ.

Every table tries its transports in the order `dot`, `doh`, `ipv6`, `ipv4`, so
encrypted transports win when the priority strategy reaches a table.  Override
that per table:

```toml
[dns.2]
order = [ "ipv4", "dot", "doh" ]
```

Transports that are configured but missing from `order` are appended in the
default order, and duplicates or an empty list are rejected.

DoT and DoH hostnames are resolved to the plain `ipv4`/`ipv6` addresses of the
same table before the system resolver is consulted, so this works even when
`/etc/resolv.conf` points at dnscacher itself:

```toml
[dns.2]
ipv4 = [ "1.1.1.1", "1.0.0.1" ]
ipv6 = [ "2606:4700:4700::1111", "2606:4700:4700::1001" ]
dot = "cloudflare-dns.com"
doh = "https://cloudflare-dns.com/dns-query"
```

Here `cloudflare-dns.com` is tried at all four addresses (in the table's
ipv6/ipv4 order), and TLS still verifies the certificate against the hostname.
If those addresses do not answer or the certificate does not match, the system
resolver is used as a fallback, so a table that pairs, say, Cloudflare plain
DNS with `cloudflare-dns.com` still works.  When the table has no plain addresses, the
hostname is resolved normally.  A `dot`/`doh` value that is already an IP
literal is used directly.

`domains` restricts a group to those names and their subdomains.  When a
query matches at least one domain-specific group, only those groups are used;
otherwise only groups without `domains` are used.  A leading `*.` requires an
extra label (`*.example.com` matches `a.example.com` but not `example.com`).

Priority strategies:

- `order` — try endpoints by table number, and within each table by its
  transport order (default `dot`, `doh`, `ipv6`, `ipv4`).
- `round-robin` — rotate the starting endpoint for every query.
- `random` — shuffle endpoints for every query.
- `all` — query every matching endpoint concurrently and use the first good
  answer.  SERVFAIL/REFUSED/FORMERR/NOTIMP responses do not count as success.

### Checking which upstream answered

Upstream selection is logged at debug level.  Either pass the filter:

```sh
./target/release/dnscacher --config example-config.toml --log-level 'dnscacher=debug'
```

or set `DNSCACHER_LOG` (`RUST_LOG` takes precedence when both are set):

```sh
DNSCACHER_LOG='dnscacher=debug' ./target/release/dnscacher --config example-config.toml
```

Every cache miss logs the table that produced the answer, plus failed attempts
along the way:

```text
DEBUG upstream attempt failed upstream=1 transport=Udp { address: 192.0.2.1:53 } error=upstream attempt timed out
DEBUG upstream response peer=127.0.0.1:43630 name=example.org. query_type=A upstream_table=2 transport=Udp { address: 1.1.1.1:53 } rcode=NoError ttl=300 cached=true
```

`upstream_table` is the `[dns.N]` table from the config and `transport` is the
exact endpoint that answered.  A cache hit logs `cache hit` instead, because no
upstream was contacted.

For service-specific log settings, see [doc/distros.md](doc/distros.md).

### DNSSEC

- `off` — do not set the DO bit upstream and strip DNSSEC records from client
  responses.
- `allow` — request DNSSEC when the client set DO and pass validation status
  (including AD) through unchanged.
- `enforce` — always request DNSSEC and require the upstream's AD bit for
  answers from clients that did not set CD.  Unvalidated answers are replaced
  with SERVFAIL.  Clients that set CD opt out of this check.

This is not a local validator: `enforce` trusts a validating upstream's AD bit.
Points to a validating resolver such as Cloudflare or Google when using it.

### Hosts, deny lists and null-address filtering

Every file in `[dns] hosts` is parsed like `/etc/hosts`:

- `192.0.2.10 host.example` adds local A/AAAA records (TTL 60) and a reverse
  PTR record.
- `0.0.0.0 ads.example` and `:: ads.example` are deny entries.
- A line containing only a domain (or a list of domains) is a deny entry.
  `daemon: client` forms from `hosts.deny` are accepted; only client tokens
  that look like domain names are used.

Deny entries answer according to `deny`:

| `deny`                                      | Answer                                                   |
|---------------------------------------------|----------------------------------------------------------|
| `nx` / `nxdomain`                           | NXDOMAIN with a synthesized SOA                          |
| `zero`                                      | `0.0.0.0` / `::`                                         |
| `loopback` / `loop`                         | `127.0.0.1` / `::1`                                      |
| `{ ip = { ipv4 = "...", ipv6 = "..." } }`   | the configured address for the queried family, else NODATA |
| `ip`                                        | the address on the deny entry, else `0.0.0.0` / `::`     |

For example:

```toml
deny = { ip = { ipv4 = "192.0.2.5" } }   # A gets this, AAAA gets NODATA
```

The same policy rewrites upstream answers that resolve only to `0.0.0.0` or
`::`, so a blocklist-style upstream can return null addresses and let dnscacher
apply the local policy:

- An A or AAAA answer made up entirely of `0.0.0.0`/`::` is rewritten.
- Mixed answers (`0.0.0.0` plus a real address) and concrete answers pass
  through unchanged.
- A CNAME chain ending in a null address is rewritten; the policy answer is
  attached to the queried name and the CNAME is dropped.
- An existing upstream NXDOMAIN is left alone; no second transformation.
- With `{ ip = ... }`, a queried family without a configured address gets
  NODATA, not `0.0.0.0`/`::`.
- The rewrite happens before the cache insert, so cache hits return exactly the
  same transformed response.
- Synthesized responses have the authenticated-data flag cleared.

Hosts files are reloaded every 60 seconds.  Lines with a real address such as
`127.0.0.1 localhost` stay local records; a `127.0.0.1`-style block list
therefore does not follow the `deny` policy.  Use `0.0.0.0` or `::` in block
lists if you want `deny` to apply.

### Redirecting domains (rewrite rules)

`[dns] rules` points at one or more AdGuard-style rule files.  Only rules with
the `$dnsrewrite` modifier are used; blocking rules and other modifiers are
left alone, so an existing blocklist can be referenced safely.

```toml
[dns]
rules = [ '/etc/dnscacher.rules' ]
```

```text
# Redirect gamespy.com and all of its subdomains to openspy.net.
||gamespy.com^$dnsrewrite=openspy.net

# The equivalent explicit form.
||example.com^$dnsrewrite=NOERROR;CNAME;example.net

# Local address overrides.
||v4.example^$dnsrewrite=192.0.2.10
||v6.example^$dnsrewrite=2001:db8::10

# Answer NXDOMAIN, REFUSED, or an empty NOERROR (NODATA).
||blocked.example^$dnsrewrite=NXDOMAIN
```

A CNAME rewrite is followed and the target is resolved through the normal
upstream selection, so a query returns `gamespy.com CNAME openspy.net` followed
by `openspy.net`'s address records.  Local rewrite chains are followed up to
eight hops and loops fail with SERVFAIL.  Synthesized records start at a
60-second TTL and clear the authenticated-data flag; the cache then applies its
configured fixed lifetime like it does for upstream records.

Also supported:

- `|example.com^` or a plain `example.com` (no `^`) matches that name only;
  `||example.com^` includes subdomains.
- `*` wildcards in the domain pattern.
- `dnstype=A|AAAA` limits a rule to specific query types.
- `@@||safe.example.com^$dnsrewrite` exempts a name from all rewrites.
- `badfilter` disables an identical rule; `important` is accepted but has no
  effect because rewrites already take priority.
- Shorthand `$dnsrewrite=1.2.3.4` / `2001:db8::1`, and the full
  `NOERROR;A;...`, `NOERROR;AAAA;...`, `NOERROR;CNAME;...` and
  `NOERROR;PTR;...` forms.
- Rules with any other modifier are ignored, matching AdGuard's rule syntax.
- Rule files are reloaded every 60 seconds, like hosts files.  If you change a
  CNAME target or remove a rule, run `--purge-cache-all` (or purge the affected
  domain) so cached rewritten answers are not served until they expire.

Rewrite rules outrank hosts deny entries but not local hosts records.  A
local hosts address or PTR record always wins.
## Behavior notes

- Queries for a name found in a hosts file are answered locally and are not
  forwarded.  Unsupported record types for that name get NODATA.
- Only single-question IN-class queries are cached.  CHAOS and other classes
  get NOTIMP.
- Every upstream attempt gets a fresh UDP socket and random message ID.
- Responses are accepted only when the ID, opcode and question match.
- Upstream DoH requests always use POST with `Content-Type: application/dns-message`.
- The server advertises a 1232-byte EDNS payload upstream and truncates UDP
  responses to the client's advertised size (512 bytes without EDNS).  DoT and
  DoH responses are never truncated.
## Maintainer

ez-me <66479626+ez-me@users.noreply.github.com>

## License

MIT.  See [LICENSE](LICENSE).
