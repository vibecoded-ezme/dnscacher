//! Configuration parsing and validation.
//!
//! The configuration format is described by `example-config.toml`.  Upstreams
//! live below `[dns]` as numbered tables (`[dns.1]`, `[dns.2]`, ...).  Every
//! upstream table may contain one or more transports: plain IPv4/IPv6, DNS
//! over HTTPS and DNS over TLS.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use url::Url;

const DEFAULT_DNS_PORT: u16 = 53;
const DEFAULT_DOT_PORT: u16 = 853;
const DEFAULT_DOH_PORT: u16 = 443;
const DEFAULT_TIMEOUT_SECS: u64 = 5;

/// Transport preference applied to every table unless it sets `order`.
pub const DEFAULT_TRANSPORT_ORDER: [TransportKind; 4] = [
    TransportKind::Dot,
    TransportKind::Doh,
    TransportKind::Ipv6,
    TransportKind::Ipv4,
];

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub dns: DnsConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.address.is_empty() {
            bail!("[server] address must contain at least one address");
        }
        if self.cache.ttl == 0 {
            bail!("[cache] ttl must be greater than zero");
        }
        if self.cache.nx == 0 {
            bail!("[cache] nx must be greater than zero");
        }
        if self.dns.timeout == 0 || self.dns.timeout > 60 {
            bail!("[dns] timeout must be between 1 and 60 seconds");
        }
        if let DenyMode::Ip {
            ipv4: None,
            ipv6: None,
        } = self.dns.deny
        {
            bail!("[dns] deny.ip must specify ipv4, ipv6, or both");
        }

        // Building the upstreams validates every table and domain pattern.
        let upstreams = self.dns.build_upstreams()?;
        if upstreams.is_empty() && self.dns.hosts.is_empty() {
            bail!("no upstream DNS servers and no hosts files configured");
        }

        Ok(())
    }

    pub fn summary(&self) -> String {
        let upstreams = self.dns.build_upstreams().unwrap_or_default();
        let mut out = String::new();
        out.push_str(&format!(
            "server: {:?}:{} control={:?}\n",
            self.server.address, self.server.port, self.server.control
        ));
        out.push_str(&format!(
            "cache: ttl={}s nx={}s persistent={:?} temporary={:?}\n",
            self.cache.ttl, self.cache.nx, self.cache.persistent, self.cache.temporary
        ));
        out.push_str(&format!(
            "dns: priority={:?} dnssec={:?} deny={:?} timeout={}s hosts={:?} rules={:?}\n",
            self.dns.priority,
            self.dns.dnssec,
            self.dns.deny,
            self.dns.timeout,
            self.dns.hosts,
            self.dns.rules
        ));
        for (idx, upstream) in upstreams.iter().enumerate() {
            out.push_str(&format!(
                "upstream #{}: {:?} domains={:?}\n",
                idx + 1,
                upstream.transport,
                upstream.domains
            ));
        }
        out
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// Fixed number of seconds a positive answer is cached, overriding the
    /// TTL returned by the upstream.
    pub ttl: u32,
    /// Fixed number of seconds a negative answer is cached, overriding the
    /// upstream SOA MINIMUM.
    pub nx: u32,
    /// Long-lived cache snapshot, loaded at startup and written periodically.
    pub persistent: Option<PathBuf>,
    /// Short-lived crash-recovery snapshot, written more frequently.
    pub temporary: Option<PathBuf>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl: 86_400,
            nx: 3_600,
            persistent: None,
            temporary: None,
        }
    }
}

impl CacheConfig {
    /// Snapshot files in write order, without duplicates.
    pub fn snapshot_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        for path in [&self.persistent, &self.temporary].into_iter().flatten() {
            if !paths.contains(path) {
                paths.push(path.clone());
            }
        }
        paths
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub address: Vec<IpAddr>,
    pub port: u16,
    /// Unix socket used by `--purge-cache` / `--purge-cache-all`.
    pub control: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: vec![
                IpAddr::from_str("127.0.0.1").expect("valid IPv4"),
                IpAddr::from_str("::1").expect("valid IPv6"),
            ],
            port: 53,
            control: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub priority: Priority,
    pub dnssec: DnssecMode,
    pub hosts: Vec<PathBuf>,
    /// AdGuard-style `$dnsrewrite` rule files.
    pub rules: Vec<PathBuf>,
    pub deny: DenyMode,
    /// Timeout for a single upstream attempt, in seconds.
    pub timeout: u64,

    /// `[dns.1]`, `[dns.2]`, ... tables.
    #[serde(flatten)]
    pub upstreams: BTreeMap<String, UpstreamConfig>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            priority: Priority::Order,
            dnssec: DnssecMode::Allow,
            hosts: Vec::new(),
            rules: Vec::new(),
            deny: DenyMode::Nx,
            timeout: DEFAULT_TIMEOUT_SECS,
            upstreams: BTreeMap::new(),
        }
    }
}

impl DnsConfig {
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs(self.timeout)
    }

    /// Turn the numbered TOML tables into a flat, ordered endpoint list.
    pub fn build_upstreams(&self) -> Result<Vec<Upstream>> {
        let mut tables: Vec<(&String, &UpstreamConfig)> = self.upstreams.iter().collect();
        tables.sort_by(|(a, _), (b, _)| {
            let an = a.parse::<u64>().ok();
            let bn = b.parse::<u64>().ok();
            match (an, bn) {
                (Some(a), Some(b)) => a.cmp(&b),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(b),
            }
        });

        let mut result = Vec::new();
        for (name, upstream) in tables {
            let domains = upstream
                .domains
                .iter()
                .map(|domain| normalize_domain(domain))
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("invalid domain list in [dns.{name}]"))?;

            let mut endpoints = TableEndpoints::default();
            if let Some(spec) = &upstream.ipv4 {
                let (addresses, port) = spec.parts(upstream.port, DEFAULT_DNS_PORT);
                for address in addresses {
                    if !address.is_ipv4() {
                        bail!("[dns.{name}] ipv4 contains the IPv6 address {address}");
                    }
                    endpoints.ipv4.push(address);
                }
                endpoints.ipv4_port = port;
            }
            if let Some(spec) = &upstream.ipv6 {
                let (addresses, port) = spec.parts(upstream.port, DEFAULT_DNS_PORT);
                for address in addresses {
                    if !address.is_ipv6() {
                        bail!("[dns.{name}] ipv6 contains the IPv4 address {address}");
                    }
                    endpoints.ipv6.push(address);
                }
                endpoints.ipv6_port = port;
            }
            if let Some(spec) = &upstream.dot {
                let (host, port) = spec.parts(upstream.port, DEFAULT_DOT_PORT);
                let host = normalize_dot_host(&host);
                if host.is_empty() {
                    bail!("[dns.{name}] dot host is empty");
                }
                endpoints.dot = Some((host, port));
            }
            if let Some(spec) = &upstream.doh {
                endpoints.doh = Some(spec.url_with_port(upstream.port)?);
            }

            if endpoints.is_empty() {
                bail!("[dns.{name}] has no ipv4, ipv6, dot or doh endpoint");
            }

            let order = transport_order(upstream.order.as_deref(), name)?;
            let hints = endpoint_hints(&endpoints, &order);

            for kind in order {
                match kind {
                    TransportKind::Ipv4 => {
                        for address in &endpoints.ipv4 {
                            result.push(Upstream {
                                transport: Transport::Udp {
                                    address: std::net::SocketAddr::new(
                                        *address,
                                        endpoints.ipv4_port,
                                    ),
                                },
                                domains: domains.clone(),
                                table: name.clone(),
                            });
                        }
                    }
                    TransportKind::Ipv6 => {
                        for address in &endpoints.ipv6 {
                            result.push(Upstream {
                                transport: Transport::Udp {
                                    address: std::net::SocketAddr::new(
                                        *address,
                                        endpoints.ipv6_port,
                                    ),
                                },
                                domains: domains.clone(),
                                table: name.clone(),
                            });
                        }
                    }
                    TransportKind::Dot => {
                        if let Some((host, port)) = &endpoints.dot {
                            result.push(Upstream {
                                transport: Transport::Dot {
                                    host: host.clone(),
                                    port: *port,
                                    hints: hints.clone(),
                                },
                                domains: domains.clone(),
                                table: name.clone(),
                            });
                        }
                    }
                    TransportKind::Doh => {
                        if let Some(url) = &endpoints.doh {
                            result.push(Upstream {
                                transport: Transport::Doh {
                                    url: url.clone(),
                                    hints: hints.clone(),
                                },
                                domains: domains.clone(),
                                table: name.clone(),
                            });
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}

#[derive(Default)]
struct TableEndpoints {
    ipv4: Vec<IpAddr>,
    ipv4_port: u16,
    ipv6: Vec<IpAddr>,
    ipv6_port: u16,
    dot: Option<(String, u16)>,
    doh: Option<Url>,
}

impl TableEndpoints {
    fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty() && self.dot.is_none() && self.doh.is_none()
    }
}

/// Resolve the per-table transport order, appending any transports the user did
/// not mention in the default order.
fn transport_order(order: Option<&[TransportKind]>, name: &str) -> Result<Vec<TransportKind>> {
    let mut resolved: Vec<TransportKind> = Vec::new();

    if let Some(order) = order {
        if order.is_empty() {
            bail!("[dns.{name}] order must not be empty");
        }
        for kind in order {
            if resolved.contains(kind) {
                bail!("[dns.{name}] order lists {kind} more than once");
            }
            resolved.push(*kind);
        }
    }

    for kind in DEFAULT_TRANSPORT_ORDER {
        if !resolved.contains(&kind) {
            resolved.push(kind);
        }
    }

    Ok(resolved)
}

/// Addresses a DoT/DoH hostname should be resolved to, taken from the plain
/// IPv4/IPv6 endpoints of the same table.
fn endpoint_hints(endpoints: &TableEndpoints, order: &[TransportKind]) -> Vec<IpAddr> {
    let mut hints = Vec::new();
    for kind in order {
        match kind {
            TransportKind::Ipv4 => hints.extend(endpoints.ipv4.iter().copied()),
            TransportKind::Ipv6 => hints.extend(endpoints.ipv6.iter().copied()),
            _ => {}
        }
    }
    hints
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Priority {
    /// Try upstreams in configuration order.
    Order,
    /// Rotate the starting upstream for every query.
    RoundRobin,
    /// Shuffle upstreams for every query.
    Random,
    /// Query every matching upstream concurrently and use the first good answer.
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnssecMode {
    /// Do not request DNSSEC records; strip them from responses.
    Off,
    /// Request DNSSEC when the client asks for it and pass the result through.
    Allow,
    /// Always request DNSSEC and require the upstream to have validated the answer.
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyMode {
    /// Answer NXDOMAIN.
    Nx,
    /// Answer 0.0.0.0 / ::.
    Zero,
    /// Answer 127.0.0.1 / ::1.
    Loopback,
    /// Answer the configured address.  A missing family produces NODATA.
    Ip {
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    },
    /// Legacy bare `"ip"`: answer the address supplied by the deny entry,
    /// falling back to 0.0.0.0 / ::.
    IpEntry,
}

/// Addresses chosen by `deny = { ip = { ipv4 = "...", ipv6 = "..." } }`.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyAddresses {
    #[serde(default)]
    pub ipv4: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub ipv6: Option<std::net::Ipv6Addr>,
}

impl<'de> Deserialize<'de> for DenyMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged, deny_unknown_fields)]
        enum Raw {
            /// `deny = "nx"`, `"zero"`, `"loopback"`, `"ip"`.
            Name(String),
            /// `deny = { ip = { ipv4 = "...", ipv6 = "..." } }`.
            Ip { ip: DenyAddresses },
        }

        match Raw::deserialize(deserializer)? {
            Raw::Name(name) => match name.to_ascii_lowercase().as_str() {
                "nx" | "nxdomain" => Ok(DenyMode::Nx),
                "zero" => Ok(DenyMode::Zero),
                "loopback" | "loop" => Ok(DenyMode::Loopback),
                "ip" => Ok(DenyMode::IpEntry),
                other => Err(serde::de::Error::custom(format!(
                    "unknown deny mode {other:?}; expected nx, zero, loopback or ip"
                ))),
            },
            Raw::Ip { ip } => Ok(DenyMode::Ip {
                ipv4: ip.ipv4,
                ipv6: ip.ipv6,
            }),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub ipv4: Option<IpSpec>,
    #[serde(default)]
    pub ipv6: Option<IpSpec>,
    #[serde(default)]
    pub dot: Option<DotSpec>,
    #[serde(default)]
    pub doh: Option<DohSpec>,
    /// Transport preference for this table, e.g. `[ "dot", "doh", "ipv6", "ipv4" ]`.
    /// Transports that are configured but not listed are appended afterwards.
    #[serde(default)]
    pub order: Option<Vec<TransportKind>>,
    /// If set, this upstream is only used for these domains (and their subdomains).
    #[serde(default)]
    pub domains: Vec<String>,
    /// Default port for transports in this table.
    #[serde(default)]
    pub port: Option<u16>,
}

/// One kind of upstream transport, as used by the per-table `order` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Ipv4,
    Ipv6,
    Dot,
    Doh,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            TransportKind::Ipv4 => "ipv4",
            TransportKind::Ipv6 => "ipv6",
            TransportKind::Dot => "dot",
            TransportKind::Doh => "doh",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum IpSpec {
    List(Vec<IpAddr>),
    Detailed {
        #[serde(alias = "ips", alias = "list")]
        addresses: Vec<IpAddr>,
        #[serde(default)]
        port: Option<u16>,
    },
}

impl IpSpec {
    fn parts(&self, table_port: Option<u16>, default_port: u16) -> (Vec<IpAddr>, u16) {
        match self {
            IpSpec::List(addresses) => (addresses.clone(), table_port.unwrap_or(default_port)),
            IpSpec::Detailed { addresses, port } => (
                addresses.clone(),
                port.or(table_port).unwrap_or(default_port),
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DotSpec {
    /// `dot = "dns.example.com"` or `dot = "dns.example.com:853"`.
    Host(String),
    Detailed {
        #[serde(alias = "name", alias = "address")]
        host: String,
        #[serde(default)]
        port: Option<u16>,
    },
}

impl DotSpec {
    fn parts(&self, table_port: Option<u16>, default_port: u16) -> (String, u16) {
        let (raw_host, explicit_port) = match self {
            DotSpec::Host(value) => (value.clone(), None),
            DotSpec::Detailed { host, port } => (host.clone(), *port),
        };

        let (host, embedded_port) = split_host_port(&raw_host);
        let port = explicit_port
            .or(embedded_port)
            .or(table_port)
            .unwrap_or(default_port);
        (host, port)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DohSpec {
    /// `doh = "https://cloudflare-dns.com/dns-query"`.
    Url(String),
    Detailed {
        #[serde(alias = "address")]
        url: String,
        #[serde(default)]
        port: Option<u16>,
    },
}

impl DohSpec {
    fn url_with_port(&self, table_port: Option<u16>) -> Result<Url> {
        let (raw, port) = match self {
            DohSpec::Url(raw) => (raw, None),
            DohSpec::Detailed { url, port } => (url, *port),
        };

        let mut url = Url::parse(raw).with_context(|| format!("invalid DoH URL {raw:?}"))?;
        if !matches!(url.scheme(), "https" | "http") {
            bail!("DoH URL {raw:?} must use http or https");
        }
        if url.has_host() {
            // Keep an explicit port from the URL, otherwise apply the configured
            // port.  443 is already the default for https and needs no change.
            if url.port().is_none() {
                if let Some(port) = port.or(table_port) {
                    if !(url.scheme() == "https" && port == DEFAULT_DOH_PORT)
                        && !(url.scheme() == "http" && port == 80)
                    {
                        url.set_port(Some(port))
                            .map_err(|_| anyhow::anyhow!("cannot set port on DoH URL"))?;
                    }
                }
            }
        } else {
            bail!("DoH URL {raw:?} has no host");
        }

        Ok(url)
    }
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub transport: Transport,
    /// Empty means this upstream handles every domain.
    pub domains: Vec<String>,
    /// The `[dns.N]` table this endpoint came from (for logging).
    pub table: String,
}

impl Upstream {
    pub fn applies_to(&self, name: &str) -> bool {
        self.domains.is_empty()
            || self
                .domains
                .iter()
                .any(|domain| domain_matches(domain, name))
    }

    pub fn is_domain_specific(&self) -> bool {
        !self.domains.is_empty()
    }
}

#[derive(Clone)]
pub enum Transport {
    /// Plain DNS over UDP, with a TCP retry when the response is truncated.
    Udp { address: std::net::SocketAddr },
    /// DNS over TLS.  `hints` are the plain addresses of the same table, used
    /// before falling back to system resolution of `host`.
    Dot {
        host: String,
        port: u16,
        hints: Vec<IpAddr>,
    },
    /// DNS over HTTPS (RFC 8484), POST with `application/dns-message`.
    Doh { url: Url, hints: Vec<IpAddr> },
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Udp { address } => f.debug_struct("Udp").field("address", address).finish(),
            Transport::Dot { host, port, hints } => f
                .debug_struct("Dot")
                .field("host", host)
                .field("port", port)
                .field("hints", hints)
                .finish(),
            Transport::Doh { url, hints } => f
                .debug_struct("Doh")
                .field("url", &url.as_str())
                .field("hints", hints)
                .finish(),
        }
    }
}

/// Lower-case a domain pattern and remove one trailing dot.
pub fn normalize_domain(domain: &str) -> Result<String> {
    let mut domain = domain.trim().to_ascii_lowercase();
    while domain.ends_with('.') {
        domain.pop();
    }
    if domain.is_empty() {
        bail!("empty domain pattern");
    }

    let bare = domain.strip_prefix("*.").unwrap_or(&domain);
    let bare = bare.strip_prefix('.').unwrap_or(bare);
    if bare.is_empty()
        || bare.len() > 253
        || bare.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        bail!("invalid domain pattern {domain:?}");
    }

    Ok(domain)
}

/// Match `pattern` against a query name.  A bare pattern matches itself and
/// every subdomain; `*.example.com` requires at least one extra label.
pub fn domain_matches(pattern: &str, name: &str) -> bool {
    let name = name.trim_end_matches('.');
    let pattern = pattern.trim_end_matches('.');

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.';
    }

    let pattern = pattern.strip_prefix('.').unwrap_or(pattern);
    name == pattern
        || (name.len() > pattern.len()
            && name.ends_with(pattern)
            && name.as_bytes()[name.len() - pattern.len() - 1] == b'.')
}

fn split_host_port(value: &str) -> (String, Option<u16>) {
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return (address.ip().to_string(), Some(address.port()));
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        return (address.to_string(), None);
    }

    // Bracketed IPv6 literal, with or without a port.
    if let Some(rest) = value.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|port| port.parse::<u16>().ok());
            return (host.to_string(), port);
        }
    }

    // A single colon separates host and port; more than one means a bare IPv6
    // literal without a port.
    if value.matches(':').count() == 1 {
        if let Some((host, port)) = value.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                return (host.to_string(), Some(port));
            }
        }
    }

    (value.to_string(), None)
}

fn normalize_dot_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> DnsConfig {
        toml::from_str(text).unwrap()
    }

    fn describe(upstreams: &[Upstream]) -> Vec<String> {
        upstreams
            .iter()
            .map(|upstream| match &upstream.transport {
                Transport::Udp { address } if address.is_ipv4() => format!("ipv4:{address}"),
                Transport::Udp { address } => format!("ipv6:{address}"),
                Transport::Dot { host, port, .. } => format!("dot:{host}:{port}"),
                Transport::Doh { url, .. } => format!("doh:{url}"),
            })
            .collect()
    }

    const TABLE: &str = r#"
["2"]
ipv4 = [ "1.1.1.1", "1.0.0.1" ]
ipv6 = [ "2606:4700:4700::1111", "2606:4700:4700::1001" ]
dot = "cloudflare-dns.com"
doh = "https://cloudflare-dns.com/dns-query"
"#;

    #[test]
    fn defaults_to_secure_transports_first() {
        let upstreams = parse(TABLE).build_upstreams().unwrap();
        assert_eq!(
            describe(&upstreams),
            vec![
                "dot:cloudflare-dns.com:853".to_string(),
                "doh:https://cloudflare-dns.com/dns-query".to_string(),
                "ipv6:[2606:4700:4700::1111]:53".to_string(),
                "ipv6:[2606:4700:4700::1001]:53".to_string(),
                "ipv4:1.1.1.1:53".to_string(),
                "ipv4:1.0.0.1:53".to_string(),
            ]
        );
    }

    #[test]
    fn secure_transports_use_same_table_addresses_as_hints() {
        let upstreams = parse(TABLE).build_upstreams().unwrap();

        let Transport::Dot { hints, .. } = &upstreams[0].transport else {
            panic!("first endpoint should be DoT");
        };
        assert_eq!(
            hints,
            &vec![
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1001".parse::<IpAddr>().unwrap(),
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "1.0.0.1".parse::<IpAddr>().unwrap(),
            ]
        );

        let Transport::Doh { hints, .. } = &upstreams[1].transport else {
            panic!("second endpoint should be DoH");
        };
        assert_eq!(hints.len(), 4);
    }

    #[test]
    fn honours_explicit_order_and_appends_the_rest() {
        let upstreams = parse(
            r#"
["2"]
order = [ "ipv4", "doh" ]
ipv4 = [ "1.1.1.1" ]
ipv6 = [ "2606:4700:4700::1111" ]
dot = "cloudflare-dns.com"
doh = "https://cloudflare-dns.com/dns-query"
"#,
        )
        .build_upstreams()
        .unwrap();

        assert_eq!(
            describe(&upstreams),
            vec![
                "ipv4:1.1.1.1:53".to_string(),
                "doh:https://cloudflare-dns.com/dns-query".to_string(),
                "dot:cloudflare-dns.com:853".to_string(),
                "ipv6:[2606:4700:4700::1111]:53".to_string(),
            ]
        );

        let Transport::Dot { hints, .. } = &upstreams[2].transport else {
            panic!("third endpoint should be DoT");
        };
        assert_eq!(
            hints,
            &vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn rejects_duplicate_order_entries() {
        let config = parse(
            r#"
["2"]
order = [ "doh", "doh" ]
ipv4 = [ "1.1.1.1" ]
doh = "https://cloudflare-dns.com/dns-query"
"#,
        );
        let error = config.build_upstreams().unwrap_err().to_string();
        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn rejects_empty_order() {
        let config = parse(
            r#"
["2"]
order = []
ipv4 = [ "1.1.1.1" ]
"#,
        );
        let error = config.build_upstreams().unwrap_err().to_string();
        assert!(error.contains("must not be empty"), "{error}");
    }

    #[derive(Deserialize)]
    struct DenyHolder {
        deny: DenyMode,
    }

    fn deny_mode(text: &str) -> DenyMode {
        toml::from_str::<DenyHolder>(text).unwrap().deny
    }

    #[test]
    fn parses_deny_policies() {
        assert_eq!(deny_mode("deny = 'nx'"), DenyMode::Nx);
        assert_eq!(deny_mode("deny = 'nxdomain'"), DenyMode::Nx);
        assert_eq!(deny_mode("deny = 'zero'"), DenyMode::Zero);
        assert_eq!(deny_mode("deny = 'loopback'"), DenyMode::Loopback);
        assert_eq!(deny_mode("deny = 'loop'"), DenyMode::Loopback);
        assert_eq!(deny_mode("deny = 'ip'"), DenyMode::IpEntry);
        assert_eq!(
            deny_mode("deny = { ip = { ipv4 = '10.0.0.1', ipv6 = 'fd00::1' } }"),
            DenyMode::Ip {
                ipv4: Some("10.0.0.1".parse().unwrap()),
                ipv6: Some("fd00::1".parse().unwrap()),
            }
        );
        assert_eq!(
            deny_mode("deny = { ip = { ipv4 = '10.0.0.1' } }"),
            DenyMode::Ip {
                ipv4: Some("10.0.0.1".parse().unwrap()),
                ipv6: None,
            }
        );
    }

    #[test]
    fn rejects_unknown_deny_mode() {
        assert!(toml::from_str::<DenyHolder>("deny = 'nope'").is_err());
    }

    #[test]
    fn rejects_empty_ip_deny() {
        let config: Config = toml::from_str(
            r#"
[dns]
deny = { ip = {} }

[dns.1]
ipv4 = [ "1.1.1.1" ]
"#,
        )
        .unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("deny.ip must specify"), "{error}");
    }
}
