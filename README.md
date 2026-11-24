# dnscacher

A small caching DNS forwarder written in Rust.  It serves ordinary DNS over
UDP and TCP as well as DNS over TLS (DoT) and DNS over HTTPS (DoH), forwards
cache misses to plain DNS, DNS over TLS (DoT) or DNS over HTTPS (DoH) upstreams,
and persists its cache across restarts.

## Features

- UDP and TCP server on any number of IPv4/IPv6 addresses.
- Optional DoT (RFC 7858) and DoH (RFC 8484) listeners that use the same cache,
  hosts files, rewrite rules and upstream selection.
- Upstream priority modes: `order`, `round-robin`, `random`, `all`.
- Plain DNS upstreams (UDP with automatic TCP retry on truncation), DoT via
  rustls, and DoH (RFC 8484 POST).
- Encrypted transports first by default (`dot`, `doh`, `ipv6`, `ipv4`), with a
  per-table `order` override.
- DoT/DoH hostnames resolve through the same table's plain addresses before
  the system resolver.
- Per-domain upstream routing, including subdomains.
- Fixed-lifetime positive and negative caching with TTL adjustment on every
  hit.
- Persistent cache snapshots (long-lived plus a frequent crash-recovery copy).
- Live cache purging by domain or in full (`--purge-cache`, `--purge-cache-all`).
- `/etc/hosts` style local records, reverse (`PTR`) lookups, deny lists, and
  policy rewriting of upstream `0.0.0.0`/`::` answers.
- AdGuard-style `$dnsrewrite` rules for CNAME redirects, address overrides and
  response-code overrides.
- DNSSEC modes: `off`, `allow`, and strict `enforce`.
- EDNS(0) with a 1232-byte upstream payload, UDP truncation for plain clients.
- Query/response matching to reject spoofed or mismatched upstream answers.

## Build and run

```sh
cargo build --release
sudo ./target/release/dnscacher --config example-config.toml
```

Release builds use fat LTO, one codegen unit, `panic = "abort"` and stripped
symbols (see `[profile.release]` in `Cargo.toml`), so the first build takes
longer but produces a smaller binary.

Port 53 needs root or `CAP_NET_BIND_SERVICE`.  For an unprivileged test run:

```sh
cargo run -- --config example-config.toml --port 5353
dog example.com @127.0.0.1:5353
```

Useful options:

```text
-c, --config <PATH>       configuration file (default /etc/dnscacher.toml)
    --port <PORT>         override [server] port
    --address <IP>        override [server] address (repeatable)
    --check               validate the config and print effective settings
    --purge-cache <DOMAIN> remove a domain and its subdomains from the cache
    --purge-cache-all     remove every cached entry
    --log-level <FILTER>  log filter (default "dnscacher=info,warn")
```

`DNSCACHER_CONFIG`, `DNSCACHER_LOG` and `RUST_LOG` are also read.

### Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
cargo deny check
```

`cargo deny` reads `deny.toml` and checks advisories, licenses, duplicate
versions and crate sources.

### Purging the cache

```sh
sudo dnscacher --purge-cache example.com   # example.com and *.example.com
sudo dnscacher --purge-cache-all
```

The running server owns the in-memory cache, so the commands talk to it over
the Unix socket configured by `[server] control` (`/run/dnscacher/control.sock`
in the packaged config).  A purge also rewrites the snapshot files immediately,
so a later restart does not resurrect the removed entries.

If the server is not running, or no `control` socket is configured, the command
falls back to rewriting `persistent`/`temporary` directly and prints a note.  In
that case a *running* server would keep its in-memory entries; configure the
control socket to avoid that.  Domain matching is label-aware: `example.com`
matches `example.com` and `www.example.com`, but not `notexample.com`.

## Run as a systemd service

The `deploy/` directory contains a hardened unit and a system-wide config.  Get
a release binary and install everything with:

```sh
cargo build --release
sudo deploy/install.sh
```

The script installs:

| Path | Purpose |
|------|---------|
| `/usr/local/bin/dnscacher` | the binary |
| `/etc/dnscacher.toml` | configuration, only written if missing |
| `/etc/systemd/system/dnscacher.service` | the unit |
| `/usr/local/share/doc/dnscacher/README.md` | this document |

It validates the config, reloads systemd, then enables and starts the service.
Pass `--force-config` to replace an existing `/etc/dnscacher.toml`, and
`--no-start` to install without starting.  Running
`sudo deploy/install.sh --build` also builds the release binary first (as root,
so make sure `cargo` is on root's `PATH`).

The unit runs as a `DynamicUser` with only `CAP_NET_BIND_SERVICE`, keeps the
cache under `/var/lib/dnscacher`, and exposes the control socket in
`/run/dnscacher/control.sock` (`RuntimeDirectory=dnscacher`), and stops with
SIGTERM so the cache is saved cleanly.

Useful commands:

```sh
systemctl status dnscacher
journalctl -u dnscacher -f
dog example.com @127.0.0.1
sudo dnscacher --purge-cache example.com
sudo systemctl disable --now dnscacher
```

To use it system-wide, point `/etc/resolv.conf` at `127.0.0.1` through your
network manager rather than editing a managed file.  DoT and DoH hostnames in a
table are resolved to that table's `ipv4`/`ipv6` addresses first, so normal
upstream tables work without touching `/etc/hosts`.  Only hosts that are not
listed in the same table fall back to the system resolver, which may loop if
that resolver is dnscacher itself; add those to `/etc/hosts` or use plain IP
upstreams.

### Uninstall

```sh
sudo deploy/uninstall.sh          # service, binary and documentation
sudo deploy/uninstall.sh --purge  # also remove /etc/dnscacher.toml and the cache
```

### Arch Linux package

`packaging/arch/` builds a normal pacman package from the current working tree:

```sh
./packaging/arch/build-local.sh       # makepkg -si, asks for sudo
```

Then manage it like any other package:

```sh
sudo systemctl enable --now dnscacher
sudo pacman -R dnscacher
```

The package installs `/usr/bin/dnscacher`, `/etc/dnscacher.toml` (a pacman
backup file), the unit in `/usr/lib/systemd/system`, and documentation in
`/usr/share/doc/dnscacher`.  It is not enabled automatically.  A modified
config is kept as `/etc/dnscacher.toml.pacsave` when you remove the package.

`build-local.sh` stages a source tarball under `target/archpkg/` and passes any
arguments to `makepkg`, so `./packaging/arch/build-local.sh -f` builds without
installing.  Don't mix it with `deploy/install.sh`: that script installs to
`/usr/local` and `/etc/systemd/system`, which would shadow the packaged unit.

### Debian package

`packaging/debian/` contains a debhelper source tree plus `build-deb.sh`, which
assembles a binary package without requiring debhelper or dpkg development
tools (it uses `ar`, `tar` and `md5sum`):

```sh
./packaging/debian/build-deb.sh        # target/debian/dnscacher_0.2.0_<arch>.deb
sudo apt install ./target/debian/dnscacher_0.2.0_amd64.deb
sudo systemctl enable --now dnscacher
```

The package installs `/usr/bin/dnscacher`, `/etc/dnscacher.toml` (a conffile),
the unit in `/usr/lib/systemd/system`, and documentation and the license in
`/usr/share/doc/dnscacher`.  It is not enabled automatically, and a modified
configuration is left in place when the package is removed.

To build with the regular Debian tooling instead:

```sh
cp -r packaging/debian debian
dpkg-buildpackage -us -uc -b
```

This needs `build-essential`, `debhelper` and a Rust toolchain (`cargo`,
`rustc`, or `rustup`).  `debian/control` declares the dependencies.

## Serving DoT and DoH

The DoT and DoH listeners are optional and disabled by default.  They share the
cache, hosts files, rewrite rules, DNSSEC policy and upstreams with the plain
server, so a name cached over UDP is also served over TLS and HTTPS.

```toml
[server]
address = [ "127.0.0.1", "::1" ]
port = 53

# DNS over TLS (RFC 7858).
[server.dot]
port = 853                    # default 853
# address = [ "127.0.0.1" ]  # optional; defaults to [server] address
cert = "/etc/dnscacher/tls/cert.pem"
key = "/etc/dnscacher/tls/key.pem"

# DNS over HTTPS (RFC 8484).
[server.doh]
port = 443                    # default 443
path = "/dns-query"           # default /dns-query
cert = "/etc/dnscacher/tls/cert.pem"
key = "/etc/dnscacher/tls/key.pem"
```

- `cert` is a PEM certificate chain, leaf certificate first.  `key` may be a
  PKCS#8, PKCS#1 (RSA) or SEC1 (EC) PEM private key.
- DoH answers only the configured path.  It accepts `POST` with
  `Content-Type: application/dns-message` and `GET` with a base64url `?dns=`
  parameter (padding optional), over HTTP/2 or HTTP/1.1; `h2` is preferred via
  ALPN.  Request bodies are limited to 65535 bytes.
- DoT speaks standard two-byte length-prefixed DNS over TLS 1.2/1.3.  Idle
  DoT connections close after five minutes; plain TCP closes after 30 seconds.
- A missing, unreadable or mismatched certificate/key pair is an error at
  startup, and `--check` validates it before the service starts.
- Ports below 1024 need `CAP_NET_BIND_SERVICE`; the packaged unit already has
  that capability.  High ports work for unprivileged testing.

### Test certificate

For a local deployment, a self-signed certificate with the right subject
alternative names is enough:

```sh
sudo install -d -m 0755 /etc/dnscacher/tls
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout /etc/dnscacher/tls/key.pem \
  -out /etc/dnscacher/tls/cert.pem \
  -subj '/CN=dnscacher' \
  -addext 'subjectAltName=DNS:dnscacher,DNS:localhost,IP:127.0.0.1'
```

Clients must trust that certificate.  `dog` uses OpenSSL's trust store, so for a
self-signed certificate point `SSL_CERT_FILE` at it; `curl --cacert` and
`kdig +tls-ca` take the file directly.  With systemd's `DynamicUser=yes`, the
private key must be readable by the service account.  Either make it
world-readable (`0644`) or pass it as a systemd credential and point `key` at
`/run/credentials/dnscacher.service/tls-key`; see the commented
`LoadCredential=` lines in `deploy/dnscacher.service`.

### Querying the listeners

`dog` speaks plain DNS, DoT and DoH, and is the simplest client:

```sh
# DoT.  Leave out SSL_CERT_FILE when the certificate is trusted system-wide.
SSL_CERT_FILE=/etc/dnscacher/tls/cert.pem \
  dog -S example.com @127.0.0.1:853

# DoH (the URL is the nameserver; -H selects HTTPS).
SSL_CERT_FILE=/etc/dnscacher/tls/cert.pem \
  dog -H example.com @https://dns.example.com/dns-query

# JSON output, handy for scripts.
SSL_CERT_FILE=/etc/dnscacher/tls/cert.pem \
  dog -H -J example.com @https://dns.example.com/dns-query
```

`dog` 0.1.0 always connects to port 443 for DoH and cannot select another port,
so a listener on 8443 needs `curl` or `kdig`.  `dig` has no DoH support; use
`dog -H`, `kdig +https`, or a browser with a custom DoH URL.

For a non-default port, or to check the HTTP details directly:

```sh
# DoH POST, where query.bin is a raw DNS query
curl --http2 --cacert /etc/dnscacher/tls/cert.pem \
  -H 'content-type: application/dns-message' \
  --data-binary @query.bin https://127.0.0.1:8443/dns-query

# DoH GET (base64url-encoded query without padding)
curl --http2 --cacert /etc/dnscacher/tls/cert.pem \
  'https://127.0.0.1:8443/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB'
```

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
# [server.doh]; see "Serving DoT and DoH" below.

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
  commands from the same binary.  See [Purging the cache](#purging-the-cache).
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

For the systemd unit, add an override:

```sh
sudo systemctl edit dnscacher
```

```ini
[Service]
Environment=DNSCACHER_LOG=dnscacher=debug
```

Then `sudo systemctl restart dnscacher` and `journalctl -u dnscacher -f`.

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

## License

MIT.  See [LICENSE](LICENSE).
