//! `/etc/hosts`-style local records and domain deny lists.
//!
//! A line whose first field is an IP address adds local A/AAAA records.  Any
//! other line is treated as a deny pattern for the requested domain.  This
//! supports both plain domain block lists and the `daemon: pattern` shape used
//! by `/etc/hosts.deny` (only tokens that look like domain names are used).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::SystemTime,
};

use tracing::{debug, info, warn};

#[derive(Debug, Clone, Default)]
pub struct Addresses {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone)]
struct DenyPattern {
    pattern: String,
    address: Option<IpAddr>,
}

#[derive(Debug, Default)]
pub struct Hosts {
    entries: HashMap<String, Addresses>,
    ptr_v4: HashMap<Ipv4Addr, String>,
    ptr_v6: HashMap<Ipv6Addr, String>,
    deny: Vec<DenyPattern>,
}

impl Hosts {
    pub fn load(paths: &[PathBuf]) -> Self {
        let mut hosts = Hosts::default();

        for path in paths {
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    debug!(path = %path.display(), "hosts file does not exist");
                    continue;
                }
                Err(error) => {
                    warn!(path = %path.display(), %error, "failed to read hosts file");
                    continue;
                }
            };

            let mut records = 0usize;
            let mut blocks = 0usize;
            for line in text.lines() {
                let (a, d) = hosts.parse_line(line);
                records += a;
                blocks += d;
            }
            info!(
                path = %path.display(),
                records,
                blocked = blocks,
                "loaded hosts file"
            );
        }

        hosts
    }

    /// Returns local address records for a name, if the name is known.
    pub fn lookup(&self, name: &str) -> Option<Addresses> {
        let name = normalize_lookup_name(name);
        self.entries.get(&name).cloned()
    }

    /// Returns the matched deny pattern's optional address.
    pub fn denied(&self, name: &str) -> Option<Option<IpAddr>> {
        let name = normalize_lookup_name(name);
        self.deny
            .iter()
            .find(|entry| domain_matches(&entry.pattern, &name))
            .map(|entry| entry.address)
    }

    /// Resolve an `in-addr.arpa` or `ip6.arpa` name to the first hostname
    /// declared for that address.
    pub fn lookup_ptr(&self, name: &str) -> Option<String> {
        match parse_arpa_name(name)? {
            IpAddr::V4(address) => self.ptr_v4.get(&address).cloned(),
            IpAddr::V6(address) => self.ptr_v6.get(&address).cloned(),
        }
    }

    fn parse_line(&mut self, line: &str) -> (usize, usize) {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            return (0, 0);
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = fields.first().copied() else {
            return (0, 0);
        };

        if let Ok(address) = first.parse::<IpAddr>() {
            // Ad-block style `0.0.0.0 domain` and `:: domain` entries are deny
            // entries, so the configured deny policy decides the answer.
            let is_deny_entry = address.is_unspecified();
            let mut records = 0;
            let mut blocks = 0;

            for host in &fields[1..] {
                if let Some(host) = normalize_hostname(host) {
                    if is_deny_entry {
                        self.deny.push(DenyPattern {
                            pattern: host,
                            address: Some(address),
                        });
                        blocks += 1;
                    } else {
                        self.add_address(address, &host);
                        records += 1;
                    }
                }
            }

            return (records, blocks);
        }

        // Non-IP lines are block/deny entries.  For hosts.deny style lines the
        // service part before the first colon is not a domain.
        let candidate_text = match line.split_once(':') {
            Some((_services, clients)) => clients,
            None => line,
        };

        let mut address_hint = None;
        let mut patterns = Vec::new();
        for token in candidate_text.split(|character: char| {
            character.is_whitespace() || character == ',' || character == ';'
        }) {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if let Ok(address) = token.parse::<IpAddr>() {
                address_hint = Some(address);
                continue;
            }
            if let Some(pattern) = normalize_block_pattern(token) {
                patterns.push(pattern);
            }
        }

        let count = patterns.len();
        for pattern in patterns {
            self.deny.push(DenyPattern {
                pattern,
                address: address_hint,
            });
        }

        (0, count)
    }

    fn add_address(&mut self, address: IpAddr, host: &str) {
        let entry = self.entries.entry(host.to_string()).or_default();
        match address {
            IpAddr::V4(address) => {
                if !entry.v4.contains(&address) {
                    entry.v4.push(address);
                }
                self.ptr_v4
                    .entry(address)
                    .or_insert_with(|| format!("{host}."));
            }
            IpAddr::V6(address) => {
                if !entry.v6.contains(&address) {
                    entry.v6.push(address);
                }
                self.ptr_v6
                    .entry(address)
                    .or_insert_with(|| format!("{host}."));
            }
        }
    }
}

/// A shared, periodically reloadable hosts table.
type FileStamps = Vec<Option<(Option<SystemTime>, u64)>>;

#[derive(Clone)]
pub struct HostsStore {
    paths: Vec<PathBuf>,
    inner: Arc<RwLock<Arc<Hosts>>>,
    stamps: Arc<Mutex<FileStamps>>,
}

impl HostsStore {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        let stamps = file_stamps(&paths);
        let hosts = Hosts::load(&paths);
        Self {
            paths,
            inner: Arc::new(RwLock::new(Arc::new(hosts))),
            stamps: Arc::new(Mutex::new(stamps)),
        }
    }

    pub fn get(&self) -> Arc<Hosts> {
        self.inner.read().expect("hosts lock poisoned").clone()
    }

    pub fn reload(&self) {
        if self.paths.is_empty() {
            return;
        }

        let stamps = file_stamps(&self.paths);
        {
            let current = self.stamps.lock().expect("hosts stamp lock poisoned");
            if *current == stamps {
                return;
            }
        }

        info!("hosts files changed, reloading");
        let hosts = Hosts::load(&self.paths);
        *self.inner.write().expect("hosts lock poisoned") = Arc::new(hosts);
        *self.stamps.lock().expect("hosts stamp lock poisoned") = stamps;
    }
}

fn file_stamps(paths: &[PathBuf]) -> FileStamps {
    paths
        .iter()
        .map(|path| {
            std::fs::metadata(path)
                .ok()
                .map(|metadata| (metadata.modified().ok(), metadata.len()))
        })
        .collect()
}

fn normalize_lookup_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_hostname(host: &str) -> Option<String> {
    let host = normalize_lookup_name(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }) {
        return None;
    }
    Some(host)
}

fn normalize_block_pattern(token: &str) -> Option<String> {
    let token = token
        .trim_matches(|character: char| {
            character == '(' || character == ')' || character == '"' || character == '\''
        })
        .trim_end_matches('.');

    let bare = token.strip_prefix("*.").unwrap_or(token);
    let bare = bare.strip_prefix('.').unwrap_or(bare);

    // A block-list entry is expected to be a dotted domain.  Requiring a dot
    // avoids interpreting hosts.deny keywords such as ALL or PARANOID as
    // domains.
    if !bare.contains('.') || bare.is_empty() || bare.len() > 253 {
        return None;
    }
    if bare.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    }) {
        return None;
    }

    Some(token.to_ascii_lowercase())
}

fn domain_matches(pattern: &str, name: &str) -> bool {
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

/// Parse a reverse (`.arpa`) name without requiring an external DNS library.
fn parse_arpa_name(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();

    if let Some(prefix) = name.strip_suffix(".in-addr.arpa") {
        let mut octets: Vec<u8> = prefix
            .split('.')
            .map(|part| part.parse::<u8>())
            .collect::<Result<_, _>>()
            .ok()?;
        if octets.len() != 4 {
            return None;
        }
        octets.reverse();
        return Some(IpAddr::V4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        )));
    }

    if let Some(prefix) = name.strip_suffix(".ip6.arpa") {
        let mut nibbles: Vec<u8> = prefix
            .split('.')
            .map(|part| u8::from_str_radix(part, 16))
            .collect::<Result<_, _>>()
            .ok()?;
        if nibbles.len() != 32 {
            return None;
        }
        nibbles.reverse();

        let mut bytes = [0u8; 16];
        for (index, chunk) in nibbles.chunks(2).enumerate() {
            bytes[index] = (chunk[0] << 4) | chunk[1];
        }
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arpa_round_trip() {
        assert_eq!(
            parse_arpa_name("1.0.0.127.in-addr.arpa."),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        );
        assert_eq!(
            parse_arpa_name(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
            ),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn domain_suffix_matching() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(domain_matches("example.com", "a.example.com"));
        assert!(!domain_matches("example.com", "notexample.com"));
        assert!(domain_matches("*.example.com", "a.example.com"));
        assert!(!domain_matches("*.example.com", "example.com"));
    }

    #[test]
    fn parses_hosts_and_deny_entries() {
        let mut hosts = Hosts::default();
        hosts.parse_line("127.0.0.1 localhost");
        hosts.parse_line("0.0.0.0 ads.example.com");
        hosts.parse_line("tracker.example.org");
        hosts.parse_line("ALL: ALL");

        let local = hosts.lookup("localhost.").expect("localhost record");
        assert_eq!(local.v4, vec![Ipv4Addr::LOCALHOST]);
        assert_eq!(
            hosts.lookup_ptr("1.0.0.127.in-addr.arpa"),
            Some("localhost.".to_string())
        );

        assert!(hosts.lookup("ads.example.com").is_none());
        assert_eq!(
            hosts.denied("sub.ads.example.com"),
            Some(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
        );
        assert_eq!(hosts.denied("tracker.example.org"), Some(None));
        assert_eq!(hosts.denied("all"), None);
        assert_eq!(hosts.denied("unrelated.example.net"), None);
    }
}
