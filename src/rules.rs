//! AdGuard-style `$dnsrewrite` rules.
//!
//! Only the response-rewrite subset of the AdGuard DNS filtering syntax is
//! implemented.  Rules without `$dnsrewrite` are ignored, so an ordinary
//! blocklist can be pointed at [`DnsConfig::rules`](crate::config::DnsConfig)
//! without accidentally changing how blocking works.
//!
//! Supported shapes:
//!
//! ```text
//! ||gamespy.com^$dnsrewrite=openspy.net
//! ||gamespy.com^$dnsrewrite=NOERROR;CNAME;openspy.net
//! ||example.com^$dnsrewrite=192.0.2.10
//! ||example.com^$dnsrewrite=NOERROR;AAAA;2001:db8::10
//! ||example.com^$dnsrewrite=NXDOMAIN
//! @@||example.com^$dnsrewrite
//! ```
//!
//! `dnstype`, `important` and `badfilter` are understood as modifiers.  Any
//! other modifier makes the rule invalid, as in AdGuard's syntax.

use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    time::SystemTime,
};

use hickory_proto::{
    op::ResponseCode,
    rr::{
        rdata::{A, AAAA, PTR},
        Name, RData, RecordType,
    },
};
use tracing::{debug, info, warn};

/// The subset of a matching rewrite that the resolver needs.
#[derive(Debug, Clone)]
pub struct Rewrite {
    /// Replace the response code (and produce an empty answer).
    pub rcode: Option<ResponseCode>,
    /// Follow a CNAME to this name and resolve it.
    pub cname: Option<Name>,
    /// Direct records for this query type.  An empty list with no `cname` and
    /// no `rcode` means NODATA.
    pub records: Vec<RData>,
}

#[derive(Debug, Clone)]
enum Action {
    Rcode(ResponseCode),
    Cname(Name),
    Records(Vec<RData>),
}

#[derive(Debug, Clone)]
struct RewriteRule {
    pattern: Pattern,
    actions: Vec<Action>,
    dnstype: Option<DnsTypeFilter>,
    /// Longer, more literal patterns win when several rules provide a CNAME.
    specificity: usize,
}

#[derive(Debug, Default)]
pub struct RuleSet {
    rewrites: Vec<RewriteRule>,
    exceptions: Vec<Pattern>,
}

impl RuleSet {
    pub fn load(paths: &[PathBuf]) -> Self {
        let mut entries: Vec<(String, String)> = Vec::new();
        for path in paths {
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    let mut lines = 0usize;
                    for line in text.lines() {
                        entries.push((path.display().to_string(), line.to_string()));
                        lines += 1;
                    }
                    debug!(path = %path.display(), lines, "read rewrite rules file");
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    debug!(path = %path.display(), "rewrite rules file does not exist");
                }
                Err(error) => {
                    warn!(path = %path.display(), %error, "failed to read rewrite rules file");
                }
            }
        }

        let set = Self::from_entries(&entries);
        if !paths.is_empty() {
            info!(
                files = paths.len(),
                rewrites = set.rewrites.len(),
                exceptions = set.exceptions.len(),
                "loaded rewrite rules"
            );
        }
        set
    }

    /// Look up the rewrite policy for a query name and record type.
    pub fn rewrite(&self, name: &str, query_type: RecordType) -> Option<Rewrite> {
        let name = normalize_name(name);
        if self.exceptions.iter().any(|pattern| pattern.matches(&name)) {
            return None;
        }

        let mut matched = false;
        let mut rcode = None;
        let mut cname: Option<(usize, Name)> = None;
        let mut records: Vec<RData> = Vec::new();

        for rule in &self.rewrites {
            if !rule.pattern.matches(&name) {
                continue;
            }
            if let Some(filter) = &rule.dnstype {
                if !filter.allows(query_type) {
                    continue;
                }
            }
            matched = true;

            for action in &rule.actions {
                match action {
                    Action::Rcode(code) => {
                        rcode.get_or_insert(*code);
                    }
                    Action::Cname(target) => {
                        if cname
                            .as_ref()
                            .is_none_or(|(specificity, _)| rule.specificity > *specificity)
                        {
                            cname = Some((rule.specificity, target.clone()));
                        }
                    }
                    Action::Records(values) => {
                        for value in values {
                            if record_applies(value, query_type) && !records.contains(value) {
                                records.push(value.clone());
                            }
                        }
                    }
                }
            }
        }

        if !matched {
            return None;
        }

        // AdGuard gives keyword rewrites priority over address/CNAME rewrites.
        if let Some(rcode) = rcode {
            return Some(Rewrite {
                rcode: Some(rcode),
                cname: None,
                records: Vec::new(),
            });
        }
        if let Some((_, cname)) = cname {
            return Some(Rewrite {
                rcode: None,
                cname: Some(cname),
                records: Vec::new(),
            });
        }
        Some(Rewrite {
            rcode: None,
            cname: None,
            records,
        })
    }

    fn from_entries(entries: &[(String, String)]) -> Self {
        let badfilters: HashSet<String> = entries
            .iter()
            .filter_map(|(_, line)| badfilter_key(line))
            .collect();

        let mut set = RuleSet::default();
        for (source, line) in entries {
            match parse_line(line) {
                Ok(Some(parsed)) if badfilters.contains(&parsed.key) => {
                    debug!(source = %source, rule = %line.trim(), "rule disabled by badfilter");
                }
                Ok(Some(parsed)) if parsed.exception => {
                    set.exceptions.push(parsed.pattern);
                }
                Ok(Some(parsed)) => set.rewrites.push(RewriteRule {
                    pattern: parsed.pattern,
                    actions: parsed.actions,
                    dnstype: parsed.dnstype,
                    specificity: parsed.specificity,
                }),
                Ok(None) => {}
                Err(error) => {
                    warn!(source = %source, rule = %line.trim(), %error, "ignoring rewrite rule");
                }
            }
        }
        set
    }
}

/// A shared, periodically reloadable rule table.
#[derive(Clone)]
pub struct RulesStore {
    paths: Vec<PathBuf>,
    inner: Arc<RwLock<Arc<RuleSet>>>,
    stamps: Arc<Mutex<FileStamps>>,
}

impl RulesStore {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        let stamps = file_stamps(&paths);
        let set = RuleSet::load(&paths);
        Self {
            paths,
            inner: Arc::new(RwLock::new(Arc::new(set))),
            stamps: Arc::new(Mutex::new(stamps)),
        }
    }

    pub fn get(&self) -> Arc<RuleSet> {
        self.inner.read().expect("rules lock poisoned").clone()
    }

    pub fn reload(&self) {
        if self.paths.is_empty() {
            return;
        }

        let stamps = file_stamps(&self.paths);
        {
            let current = self.stamps.lock().expect("rules stamp lock poisoned");
            if *current == stamps {
                return;
            }
        }

        info!("rewrite rules changed, reloading");
        let set = RuleSet::load(&self.paths);
        *self.inner.write().expect("rules lock poisoned") = Arc::new(set);
        *self.stamps.lock().expect("rules stamp lock poisoned") = stamps;
    }
}

type FileStamps = Vec<Option<(Option<SystemTime>, u64)>>;

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

#[derive(Debug)]
struct ParsedRule {
    exception: bool,
    pattern: Pattern,
    actions: Vec<Action>,
    dnstype: Option<DnsTypeFilter>,
    specificity: usize,
    key: String,
}

fn parse_line(line: &str) -> Result<Option<ParsedRule>, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return Ok(None);
    }

    let (exception, body) = match line.strip_prefix("@@") {
        Some(body) => (true, body),
        None => (false, line),
    };

    let (pattern_text, modifiers_text) = match body.split_once('$') {
        Some((pattern, modifiers)) => (pattern.trim(), Some(modifiers)),
        None => (body.trim(), None),
    };

    // Without a `$` this is an AdGuard blocking rule.  This feature only owns
    // rewrite rules, so leave everything else alone.
    let Some(modifiers_text) = modifiers_text else {
        return Ok(None);
    };

    let mut rewrite_values: Vec<String> = Vec::new();
    let mut saw_dnsrewrite = false;
    let mut dnstype = None;
    let mut key_parts: Vec<String> = Vec::new();

    for raw in split_modifiers(modifiers_text) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (key, value) = match raw.split_once('=') {
            Some((key, value)) => (key.trim(), Some(value)),
            None => (raw, None),
        };
        let lower = key.to_ascii_lowercase();
        match lower.as_str() {
            "dnsrewrite" => {
                saw_dnsrewrite = true;
                match value {
                    Some(value) => {
                        rewrite_values.push(value.to_string());
                        key_parts.push(format!("dnsrewrite={}", value.to_ascii_lowercase()));
                    }
                    None if exception => {}
                    None => {
                        return Err("dnsrewrite needs a value".to_string());
                    }
                }
            }
            "dnstype" => {
                let value = value.ok_or_else(|| "dnstype needs a value".to_string())?;
                dnstype = Some(DnsTypeFilter::parse(value)?);
                key_parts.push(format!("dnstype={}", value.to_ascii_lowercase()));
            }
            // Rewrites already have priority; this is accepted for
            // compatibility with filter lists.
            "important" => {}
            // The caller turns badfilter into a set of disabled rules.
            "badfilter" => {}
            other => {
                return Err(format!("unsupported modifier {other:?}"));
            }
        }
    }

    if !saw_dnsrewrite {
        return Ok(None);
    }

    let pattern = Pattern::parse(pattern_text)?;
    let specificity = pattern.specificity();
    let mut actions = Vec::new();
    for value in rewrite_values {
        actions.push(parse_rewrite(&value)?);
    }

    if exception {
        return Ok(Some(ParsedRule {
            exception: true,
            pattern,
            actions: Vec::new(),
            dnstype,
            specificity,
            key: String::new(),
        }));
    }

    if actions.is_empty() {
        return Err("dnsrewrite has no value".to_string());
    }

    key_parts.sort();
    let key = format!(
        "{}\u{1}{}",
        pattern_text.to_ascii_lowercase(),
        key_parts.join("\u{1}")
    );

    Ok(Some(ParsedRule {
        exception: false,
        pattern,
        actions,
        dnstype,
        specificity,
        key,
    }))
}

/// Split a modifier list on commas, keeping quoted values intact.
fn split_modifiers(text: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut quote = None;
    let mut escaped = false;

    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current) = quote {
            if character == current {
                quote = None;
            }
            continue;
        }
        if character == '\'' || character == '"' {
            quote = Some(character);
            continue;
        }
        if character == ',' {
            parts.push(&text[start..index]);
            start = index + 1;
        }
    }
    parts.push(&text[start..]);
    parts
}

fn badfilter_key(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return None;
    }
    let body = line.strip_prefix("@@").unwrap_or(line);
    let (pattern, modifiers) = body.split_once('$')?;

    let mut found = false;
    let mut keep = Vec::new();
    for raw in split_modifiers(modifiers) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let key = raw
            .split_once('=')
            .map(|(key, _)| key)
            .unwrap_or(raw)
            .trim();
        if key.eq_ignore_ascii_case("badfilter") {
            found = true;
        } else {
            let key = match raw.split_once('=') {
                Some((key, value)) => {
                    format!(
                        "{}={}",
                        key.trim().to_ascii_lowercase(),
                        value.to_ascii_lowercase()
                    )
                }
                None => raw.to_ascii_lowercase(),
            };
            keep.push(key);
        }
    }
    if !found {
        return None;
    }
    keep.sort();
    Some(format!(
        "{}\u{1}{}",
        pattern.trim().to_ascii_lowercase(),
        keep.join("\u{1}")
    ))
}

fn parse_rewrite(value: &str) -> Result<Action, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("dnsrewrite needs a value".to_string());
    }

    // Keywords are case-sensitive in AdGuard.  Detect near-misses so a domain
    // literally named "nxdomain" is not silently used as a CNAME target.
    for keyword in ["NOERROR", "NXDOMAIN", "REFUSED"] {
        if value.eq_ignore_ascii_case(keyword) {
            if value != keyword {
                return Err(format!("rewrite keyword {value:?} must be {keyword}"));
            }
            return Ok(Action::Rcode(match keyword {
                "NXDOMAIN" => ResponseCode::NXDomain,
                "REFUSED" => ResponseCode::Refused,
                _ => ResponseCode::NoError,
            }));
        }
    }

    if value.contains(';') {
        let parts: Vec<&str> = value.splitn(3, ';').collect();
        if parts.len() != 3 {
            return Err(format!(
                "invalid dnsrewrite {value:?}; expected RCODE;RRTYPE;VALUE"
            ));
        }
        let rcode = match parts[0].trim().to_ascii_uppercase().as_str() {
            "NOERROR" => ResponseCode::NoError,
            "NXDOMAIN" => ResponseCode::NXDomain,
            "REFUSED" => ResponseCode::Refused,
            other => return Err(format!("unsupported rewrite response code {other:?}")),
        };
        let record_type = parts[1].trim();
        let record_value = parts[2].trim();

        if record_type.is_empty() {
            if !record_value.is_empty() {
                return Err(format!("invalid dnsrewrite {value:?}"));
            }
            return Ok(Action::Rcode(rcode));
        }
        if rcode != ResponseCode::NoError {
            return Err("only NOERROR can carry a record value".to_string());
        }
        return parse_records(record_type, record_value);
    }

    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(match address {
            IpAddr::V4(address) => Action::Records(vec![RData::A(A(address))]),
            IpAddr::V6(address) => Action::Records(vec![RData::AAAA(AAAA(address))]),
        });
    }

    Ok(Action::Cname(parse_name(value)?))
}

fn parse_records(record_type: &str, value: &str) -> Result<Action, String> {
    match record_type.to_ascii_uppercase().as_str() {
        "CNAME" => Ok(Action::Cname(parse_name(value)?)),
        "A" => {
            let address: Ipv4Addr = value
                .parse()
                .map_err(|_| format!("invalid IPv4 address {value:?}"))?;
            Ok(Action::Records(vec![RData::A(A(address))]))
        }
        "AAAA" => {
            let address: Ipv6Addr = value
                .parse()
                .map_err(|_| format!("invalid IPv6 address {value:?}"))?;
            Ok(Action::Records(vec![RData::AAAA(AAAA(address))]))
        }
        "PTR" => Ok(Action::Records(vec![RData::PTR(PTR(parse_name(value)?))])),
        other => Err(format!("unsupported rewrite record type {other:?}")),
    }
}

fn parse_name(value: &str) -> Result<Name, String> {
    let value = value.trim();
    if value.is_empty() || value.contains('*') || value.chars().any(char::is_whitespace) {
        return Err(format!("invalid domain name {value:?}"));
    }
    let value = value.trim_end_matches('.');
    if value.is_empty() || value.len() > 253 {
        return Err(format!("invalid domain name {value:?}"));
    }
    Name::from_ascii(format!("{value}."))
        .map_err(|error| format!("invalid domain name {value:?}: {error}"))
}

fn record_applies(value: &RData, query_type: RecordType) -> bool {
    matches!(
        (value, query_type),
        (RData::A(_), RecordType::A | RecordType::ANY)
            | (RData::AAAA(_), RecordType::AAAA | RecordType::ANY)
            | (RData::PTR(_), RecordType::PTR | RecordType::ANY)
    )
}

#[derive(Debug, Clone)]
struct DnsTypeFilter {
    include: Vec<RecordType>,
    exclude: Vec<RecordType>,
}

impl DnsTypeFilter {
    fn parse(value: &str) -> Result<Self, String> {
        let mut include = Vec::new();
        let mut exclude = Vec::new();
        for part in value.split('|') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (negated, name) = match part.strip_prefix('~') {
                Some(name) => (true, name),
                None => (false, part),
            };
            let record_type = RecordType::from_str(&name.to_ascii_uppercase())
                .map_err(|_| format!("unknown DNS type {name:?}"))?;
            if negated {
                exclude.push(record_type);
            } else {
                include.push(record_type);
            }
        }
        if include.is_empty() && exclude.is_empty() {
            return Err("dnstype needs at least one type".to_string());
        }
        Ok(Self { include, exclude })
    }

    fn allows(&self, query_type: RecordType) -> bool {
        if !self.include.is_empty() {
            return self.include.contains(&query_type);
        }
        !self.exclude.contains(&query_type)
    }
}

#[derive(Debug, Clone)]
struct Pattern {
    kind: PatternKind,
}

#[derive(Debug, Clone)]
enum PatternKind {
    /// `||example.com^`: the name itself and every subdomain.
    DomainSuffix(String),
    /// A plain domain or `|example.com^`: exactly this name.
    Exact(String),
    /// Adblock-style wildcard pattern with the requested anchors.
    Glob {
        pattern: String,
        domain_anchor: bool,
        start_anchor: bool,
        end_anchor: bool,
    },
}

impl Pattern {
    fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty rule pattern".to_string());
        }
        if text.starts_with('/') && text.ends_with('/') {
            return Err("regular expression rules are not supported".to_string());
        }

        let mut pattern = text.to_ascii_lowercase();
        let domain_anchor = pattern.starts_with("||");
        if domain_anchor {
            pattern.drain(..2);
        } else if let Some(rest) = pattern.strip_prefix('|') {
            pattern = rest.to_string();
        }
        let start_anchor = !domain_anchor && text.starts_with('|');

        let mut end_anchor = false;
        while pattern.ends_with('^') || pattern.ends_with('|') {
            end_anchor = true;
            pattern.pop();
        }

        if pattern.is_empty() {
            return Err("empty rule pattern".to_string());
        }

        let kind = if pattern.contains('*') {
            PatternKind::Glob {
                pattern,
                domain_anchor,
                start_anchor,
                end_anchor,
            }
        } else if domain_anchor {
            PatternKind::DomainSuffix(pattern)
        } else if !start_anchor && !end_anchor && is_domain_name(&pattern) {
            // A plain domain is an exact host rule in AdGuard's syntax.
            PatternKind::Exact(pattern)
        } else if start_anchor && end_anchor {
            PatternKind::Exact(pattern)
        } else {
            PatternKind::Glob {
                pattern,
                domain_anchor: false,
                start_anchor,
                end_anchor,
            }
        };

        Ok(Self { kind })
    }

    fn specificity(&self) -> usize {
        match &self.kind {
            PatternKind::DomainSuffix(value) | PatternKind::Exact(value) => value.len(),
            PatternKind::Glob { pattern, .. } => pattern.chars().filter(|c| *c != '*').count(),
        }
    }

    fn matches(&self, name: &str) -> bool {
        match &self.kind {
            PatternKind::DomainSuffix(suffix) => is_label_suffix(name, suffix),
            PatternKind::Exact(exact) => name == exact,
            PatternKind::Glob {
                pattern,
                domain_anchor,
                start_anchor,
                end_anchor,
            } => {
                if *domain_anchor {
                    return label_boundaries(name).any(|index| glob_match(pattern, &name[index..]));
                }
                if *start_anchor && *end_anchor {
                    return glob_match(pattern, name);
                }
                if *start_anchor {
                    return (1..=name.len()).any(|end| glob_match(pattern, &name[..end]));
                }
                if *end_anchor {
                    return (0..name.len()).any(|start| glob_match(pattern, &name[start..]));
                }
                (0..=name.len()).any(|start| {
                    (start..=name.len()).any(|end| glob_match(pattern, &name[start..end]))
                })
            }
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            PatternKind::DomainSuffix(value) => write!(formatter, "||{value}^"),
            PatternKind::Exact(value) => write!(formatter, "{value}"),
            PatternKind::Glob { pattern, .. } => write!(formatter, "{pattern}"),
        }
    }
}

fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn is_domain_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn is_label_suffix(name: &str, suffix: &str) -> bool {
    name == suffix
        || (name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

fn label_boundaries(name: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(name.match_indices('.').map(|(index, _)| index + 1))
}

/// Match a shell-style `*` pattern against the whole text.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star = None;
    let mut resume = 0usize;

    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == text[ti] {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(star_index) = star {
            pi = star_index + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> RuleSet {
        let entries: Vec<(String, String)> = text
            .lines()
            .map(|line| ("<test>".to_string(), line.to_string()))
            .collect();
        RuleSet::from_entries(&entries)
    }

    #[test]
    fn parses_shorthand_cname_rewrites() {
        let set = rules("||gamespy.com^$dnsrewrite=openspy.net\n");
        let rewrite = set.rewrite("gamespy.com", RecordType::A).unwrap();
        assert_eq!(rewrite.cname.unwrap().to_ascii(), "openspy.net.");
        assert_eq!(
            set.rewrite("master.gamespy.com", RecordType::A)
                .unwrap()
                .cname
                .unwrap()
                .to_ascii(),
            "openspy.net."
        );
        assert!(set.rewrite("notgamespy.com", RecordType::A).is_none());
    }

    #[test]
    fn parses_full_cname_syntax_and_comments() {
        let text = "\
! comment
# another comment
||example.com^$dnsrewrite=NOERROR;CNAME;example.net.
";
        let set = rules(text);
        let rewrite = set.rewrite("example.com.", RecordType::AAAA).unwrap();
        assert_eq!(rewrite.cname.unwrap().to_ascii(), "example.net.");
    }

    #[test]
    fn rewrites_addresses_and_rcodes() {
        let set = rules(
            "\
||v4.test^$dnsrewrite=192.0.2.10
||v6.test^$dnsrewrite=2001:db8::10
||nx.test^$dnsrewrite=NXDOMAIN
",
        );
        let v4 = set.rewrite("v4.test", RecordType::A).unwrap();
        assert!(
            matches!(v4.records.as_slice(), [RData::A(address)] if address.0.to_string() == "192.0.2.10")
        );
        assert!(set
            .rewrite("v4.test", RecordType::AAAA)
            .unwrap()
            .records
            .is_empty());
        let v6 = set.rewrite("v6.test", RecordType::AAAA).unwrap();
        assert!(matches!(v6.records.as_slice(), [RData::AAAA(_)]));
        assert_eq!(
            set.rewrite("nx.test", RecordType::A).unwrap().rcode,
            Some(ResponseCode::NXDomain)
        );
    }

    #[test]
    fn plain_domains_match_exactly_but_domain_anchor_matches_subdomains() {
        let set = rules("example.org$dnsrewrite=192.0.2.10\n");
        assert!(set.rewrite("example.org", RecordType::A).is_some());
        assert!(set.rewrite("www.example.org", RecordType::A).is_none());

        let set = rules("||example.org^$dnsrewrite=192.0.2.10\n");
        assert!(set.rewrite("example.org", RecordType::A).is_some());
        assert!(set.rewrite("www.example.org", RecordType::A).is_some());
        assert!(set.rewrite("notexample.org", RecordType::A).is_none());
    }

    #[test]
    fn exception_rules_disable_rewrites() {
        let set = rules(
            "\
||example.org^$dnsrewrite=192.0.2.10
@@||safe.example.org^$dnsrewrite
",
        );
        assert!(set.rewrite("example.org", RecordType::A).is_some());
        assert!(set.rewrite("safe.example.org", RecordType::A).is_none());
    }

    #[test]
    fn dnstype_and_unknown_modifiers() {
        let set = rules(
            "\
||a.test^$dnstype=AAAA,dnsrewrite=NOERROR;AAAA;2001:db8::1
||b.test^$client=127.0.0.1,dnsrewrite=192.0.2.1
",
        );
        assert!(set.rewrite("a.test", RecordType::A).is_none());
        assert!(set.rewrite("a.test", RecordType::AAAA).is_some());
        // A rule with an unsupported modifier is ignored as a whole.
        assert!(set.rewrite("b.test", RecordType::A).is_none());
    }

    #[test]
    fn badfilter_disables_a_rule() {
        let set = rules(
            "\
||ads.test^$dnsrewrite=192.0.2.10
||ads.test^$dnsrewrite=192.0.2.10,badfilter
",
        );
        assert!(set.rewrite("ads.test", RecordType::A).is_none());
    }

    #[test]
    fn more_specific_cname_wins() {
        let set = rules(
            "\
||example.com^$dnsrewrite=broad.net
||deep.example.com^$dnsrewrite=specific.net
",
        );
        assert_eq!(
            set.rewrite("deep.example.com", RecordType::A)
                .unwrap()
                .cname
                .unwrap()
                .to_ascii(),
            "specific.net."
        );
        assert_eq!(
            set.rewrite("example.com", RecordType::A)
                .unwrap()
                .cname
                .unwrap()
                .to_ascii(),
            "broad.net."
        );
    }

    #[test]
    fn rejects_invalid_rules() {
        assert!(parse_line("||example.com^$dnsrewrite=nxdomain")
            .unwrap_err()
            .contains("must be NXDOMAIN"));
        assert!(
            parse_line("||example.com^$dnsrewrite=NOERROR;MX;10 mail.test")
                .unwrap_err()
                .contains("unsupported rewrite record type")
        );
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("*.example.com", "a.example.com"));
        assert!(glob_match("*.example.com", "a.b.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(glob_match("*", ""));
    }
}
