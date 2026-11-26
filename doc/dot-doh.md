# DNS over TLS and DNS over HTTPS

[Back to README](../README.md)

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
`LoadCredential=` lines in `deploy/dnscacher.service`.  The Artix OpenRC, dinit,
runit and s6 services run as root, so the key only needs to be readable by root
there.  The Alpine OpenRC package runs as the `dnscacher` user; make the key
readable by that account, for example with group `dnscacher` and mode `0640`.

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
