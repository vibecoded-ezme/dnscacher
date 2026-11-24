//! In-memory answer cache plus a compact on-disk snapshot format.
//!
//! Responses are stored as DNS wire messages together with their insertion
//! time.  When a cached answer is served, all record TTLs are decreased by the
//! time it has spent in the cache.  The configured `ttl`/`nx` values are fixed
//! lifetimes: they override the TTLs returned by the upstream and rewrite the
//! stored records to count down from that value.  Signed responses (those with
//! RRSIGs) keep an upstream-derived TTL capped by the configured value so
//! signatures are never served past their validity.  Only successful answers
//! (NOERROR) and NXDOMAIN/NODATA responses are cached; SERVFAIL and friends are
//! not.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, RecordType},
};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::{domain_matches, CacheConfig};

const CACHE_VERSION: u32 = 2;
const MAX_CACHE_ENTRIES: u64 = 100_000;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;

static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    /// Lower-case, fully qualified query name.
    pub name: String,
    pub query_type: u16,
    pub query_class: u16,
    /// Effective DNSSEC-OK state of the upstream query.
    pub dnssec_ok: bool,
    /// CD responses can contain unvalidated data, so keep them separate.
    pub checking_disabled: bool,
}

impl CacheKey {
    pub fn from_query(message: &Message, dnssec_ok: bool) -> Option<Self> {
        let query = message.queries.first()?;
        if message.queries.len() != 1 {
            return None;
        }
        Some(Self {
            name: query.name.to_lowercase().to_ascii(),
            query_type: u16::from(query.query_type),
            query_class: u16::from(query.query_class),
            dnssec_ok,
            checking_disabled: message.metadata.checking_disabled,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub message: Message,
    pub stored_at: u64,
    pub expires_at: u64,
    pub negative: bool,
}

pub struct DnsCache {
    inner: Cache<CacheKey, CacheEntry>,
    ttl: u32,
    negative_ttl: u32,
    /// Serializes snapshot writes so a save that started before a purge cannot
    /// land after the purge's save and resurrect the removed entries.
    save_lock: tokio::sync::Mutex<()>,
}

impl DnsCache {
    pub fn new(ttl: u32, negative_ttl: u32) -> Self {
        Self {
            inner: Cache::builder().max_capacity(MAX_CACHE_ENTRIES).build(),
            ttl,
            negative_ttl,
            save_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let entry = self.inner.get(key).await?;
        if entry.expires_at <= now_unix() {
            self.inner.invalidate(key).await;
            return None;
        }
        Some(entry)
    }

    /// Remove every entry whose name is `domain` or a subdomain of it.
    /// Returns the number of entries removed.
    pub async fn purge_domain(&self, domain: &str) -> usize {
        self.inner.run_pending_tasks().await;
        let keys: Vec<CacheKey> = self
            .inner
            .iter()
            .filter(|(key, _)| domain_matches(domain, &key.name))
            .map(|(key, _)| (*key).clone())
            .collect();

        for key in &keys {
            self.inner.invalidate(key).await;
        }
        self.inner.run_pending_tasks().await;
        keys.len()
    }

    /// Remove every cached entry.  Returns the number of entries removed.
    pub async fn purge_all(&self) -> usize {
        self.inner.run_pending_tasks().await;
        let removed = self.inner.entry_count() as usize;
        self.inner.invalidate_all();
        self.inner.run_pending_tasks().await;
        removed
    }

    /// Write every configured snapshot path, ignoring duplicates.
    pub async fn save_to_config(&self, config: &CacheConfig) -> Result<()> {
        for path in config.snapshot_paths() {
            self.save_to(&path)
                .await
                .with_context(|| format!("failed to save {}", path.display()))?;
        }
        Ok(())
    }

    /// Insert a response if it is cacheable, rewriting its record TTLs to the
    /// configured lifetime.  Returns the effective TTL on success.
    pub async fn insert(&self, key: CacheKey, response: &mut Message) -> Option<u32> {
        let (ttl, negative, rewrite_ttls) = self.cache_ttl(response)?;
        let now = now_unix();

        if rewrite_ttls {
            override_ttls(response, ttl);
        }
        let message = response.clone();

        let entry = CacheEntry {
            message,
            stored_at: now,
            expires_at: now.saturating_add(u64::from(ttl)),
            negative,
        };

        debug!(
            name = %key.name,
            query_type = key.query_type,
            ttl,
            negative,
            "caching response"
        );
        self.inner.insert(key, entry).await;
        Some(ttl)
    }

    /// Returns `(lifetime, negative, rewrite_ttls)`.
    fn cache_ttl(&self, response: &Message) -> Option<(u32, bool, bool)> {
        if response.metadata.truncation {
            return None;
        }
        if !matches!(
            response.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            return None;
        }

        let negative = response.metadata.response_code == ResponseCode::NXDomain
            || response.answers.is_empty();

        // Explicit zero TTLs still mean "do not cache", even though the
        // configured lifetime overrides the server's actual TTL.
        if negative {
            // RFC 2308: negative caching TTL is the SOA MINIMUM field, further
            // limited by the SOA record's own TTL.
            let soa_ttl = response
                .authorities
                .iter()
                .chain(response.additionals.iter())
                .find_map(|record| match &record.data {
                    RData::SOA(soa) => Some(soa.minimum.min(record.ttl)),
                    _ => None,
                });
            if soa_ttl == Some(0) {
                return None;
            }

            if signed(response) {
                // Do not outlive signatures in DNSSEC negative proofs.
                let ttl = soa_ttl.unwrap_or(self.negative_ttl).min(self.negative_ttl);
                (ttl > 0).then_some((ttl, true, false))
            } else {
                (self.negative_ttl > 0).then_some((self.negative_ttl, true, true))
            }
        } else {
            let min_record_ttl = response
                .all_sections()
                .filter(|record| record.record_type() != RecordType::OPT)
                .map(|record| record.ttl)
                .min()?;
            if min_record_ttl == 0 {
                return None;
            }

            if signed(response) {
                // Rewriting TTLs upward would make RRSIGs outlive their
                // validity, so signed answers keep the upstream-derived TTL.
                let ttl = min_record_ttl.min(self.ttl);
                (ttl > 0).then_some((ttl, false, false))
            } else {
                (self.ttl > 0).then_some((self.ttl, false, true))
            }
        }
    }

    /// Snapshot every unexpired entry for persistence.
    pub fn snapshot(&self) -> Vec<(CacheKey, CacheEntry)> {
        let now = now_unix();
        self.inner
            .iter()
            .filter(|(_, entry)| entry.expires_at > now)
            .map(|(key, entry)| ((*key).clone(), entry))
            .collect()
    }

    pub async fn save_to(&self, path: &Path) -> Result<()> {
        let _guard = self.save_lock.lock().await;
        let entries = self.snapshot();
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || write_snapshot(&path, entries))
            .await
            .context("cache snapshot task panicked")??;
        Ok(())
    }

    pub async fn load_from_config(&self, config: &CacheConfig) -> Result<()> {
        let mut loaded = 0usize;
        for path in config.snapshot_paths() {
            if !path.exists() {
                debug!(path = %path.display(), "cache snapshot does not exist");
                continue;
            }

            let path_for_task = path.clone();
            match tokio::task::spawn_blocking(move || read_snapshot(&path_for_task)).await {
                Ok(Ok(entries)) => {
                    let count = entries.len();
                    for (key, entry) in entries {
                        self.inner.insert(key, entry).await;
                    }
                    loaded += count;
                    info!(path = %path.display(), entries = count, "loaded cache snapshot");
                }
                Ok(Err(error)) => {
                    warn!(path = %path.display(), %error, "failed to load cache snapshot");
                }
                Err(error) => {
                    warn!(path = %path.display(), %error, "cache load task failed");
                }
            }
        }

        if loaded > 0 {
            info!(entries = loaded, "cache warm");
        }
        Ok(())
    }
}

/// Responses carrying RRSIGs must not have their TTLs extended, otherwise
/// signatures could be served past their validity.
fn signed(response: &Message) -> bool {
    response
        .all_sections()
        .any(|record| record.record_type() == RecordType::RRSIG)
}

/// Rewrite every non-OPT record TTL to the cache lifetime, so clients see the
/// configured override and count down from it.
fn override_ttls(message: &mut Message, ttl: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        if record.record_type() != RecordType::OPT {
            record.ttl = ttl;
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskCache {
    version: u32,
    entries: Vec<DiskEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskEntry {
    key: CacheKey,
    wire: Vec<u8>,
    stored_at: u64,
    expires_at: u64,
    negative: bool,
}

fn write_snapshot(path: &Path, entries: Vec<(CacheKey, CacheEntry)>) -> Result<()> {
    let mut disk_entries = Vec::with_capacity(entries.len());
    for (key, entry) in entries {
        let wire = match entry.message.to_vec() {
            Ok(wire) => wire,
            Err(error) => {
                warn!(name = %key.name, %error, "skipping unserializable cache entry");
                continue;
            }
        };
        disk_entries.push(DiskEntry {
            key,
            wire,
            stored_at: entry.stored_at,
            expires_at: entry.expires_at,
            negative: entry.negative,
        });
    }

    write_disk(
        path,
        &DiskCache {
            version: CACHE_VERSION,
            entries: disk_entries,
        },
    )
}

fn write_disk(path: &Path, disk: &DiskCache) -> Result<()> {
    let bytes = postcard::to_stdvec(&disk).context("failed to encode cache snapshot")?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = PathBuf::from(temporary);

    let result = (|| -> Result<()> {
        std::fs::write(&temporary, &bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        {
            let file = std::fs::File::open(&temporary)
                .with_context(|| format!("failed to reopen {}", temporary.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to sync {}", temporary.display()))?;
        }
        std::fs::rename(&temporary, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result?;

    debug!(
        path = %path.display(),
        entries = disk.entries.len(),
        bytes = bytes.len(),
        "saved cache snapshot"
    );
    Ok(())
}

fn read_disk(path: &Path) -> Result<DiskCache> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() > MAX_SNAPSHOT_BYTES {
        bail!(
            "cache snapshot {} is too large ({} bytes)",
            path.display(),
            metadata.len()
        );
    }

    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let (disk, remainder): (DiskCache, &[u8]) = postcard::take_from_bytes(&bytes)
        .with_context(|| format!("failed to decode {}", path.display()))?;
    if !remainder.is_empty() {
        bail!(
            "cache snapshot {} has {} trailing bytes",
            path.display(),
            remainder.len()
        );
    }
    if disk.version != CACHE_VERSION {
        bail!(
            "unsupported cache version {} (expected {})",
            disk.version,
            CACHE_VERSION
        );
    }

    Ok(disk)
}

fn read_snapshot(path: &Path) -> Result<Vec<(CacheKey, CacheEntry)>> {
    let disk = read_disk(path)?;
    let now = now_unix();
    let mut entries = Vec::with_capacity(disk.entries.len());
    for entry in disk.entries {
        if entry.expires_at <= now {
            continue;
        }
        let message = match Message::from_vec(&entry.wire) {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "skipping corrupt cache entry");
                continue;
            }
        };
        entries.push((
            entry.key,
            CacheEntry {
                message,
                stored_at: entry.stored_at,
                expires_at: entry.expires_at,
                negative: entry.negative,
            },
        ));
    }

    Ok(entries)
}

/// Remove entries matching `domain` (or every entry when `domain` is None) from
/// a snapshot file without loading the DNS messages.  Returns the number of
/// entries removed; a missing file counts as zero.
pub fn purge_snapshot_file(path: &Path, domain: Option<&str>) -> Result<usize> {
    match std::fs::metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to stat {}", path.display()));
        }
    }

    let mut disk = read_disk(path)?;
    let before = disk.entries.len();
    match domain {
        Some(domain) => disk
            .entries
            .retain(|entry| !domain_matches(domain, &entry.key.name)),
        None => disk.entries.clear(),
    }
    let removed = before - disk.entries.len();
    write_disk(path, &disk)?;
    debug!(
        path = %path.display(),
        removed,
        remaining = disk.entries.len(),
        "purged cache snapshot"
    );
    Ok(removed)
}

/// Normalize a CLI purge target and reject names that cannot appear as a
/// cache key.  Wildcards are not accepted.
pub fn normalize_purge_domain(value: &str) -> Result<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        bail!("domain must not be empty");
    }
    if domain.len() > 253
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        bail!("invalid domain {value:?}");
    }
    Ok(domain)
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{
            rdata::{A, NULL, SOA},
            Name, RData, Record, RecordType,
        },
    };

    use super::*;

    fn positive_response(ttl: u32) -> Message {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.recursion_available = true;
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        message
    }

    #[tokio::test]
    async fn overrides_upstream_ttl() {
        let cache = DnsCache::new(300, 60);
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let key = CacheKey::from_query(&query, false).unwrap();
        // The upstream says 120 seconds, but the configured lifetime wins.
        let mut response = positive_response(120);
        assert_eq!(cache.insert(key.clone(), &mut response).await, Some(300));
        assert_eq!(response.answers[0].ttl, 300);
        let entry = cache.get(&key).await.unwrap();
        assert_eq!(entry.message.answers[0].ttl, 300);
    }

    #[tokio::test]
    async fn signed_answers_keep_upstream_ttl() {
        let cache = DnsCache::new(300, 60);
        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let key = CacheKey::from_query(&query, false).unwrap();
        let mut response = positive_response(120);
        // An RRSIG-typed record marks the answer as signed.
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            RData::Unknown {
                code: RecordType::RRSIG,
                rdata: NULL::with(vec![0]),
            },
        ));
        assert_eq!(cache.insert(key.clone(), &mut response).await, Some(120));
        let entry = cache.get(&key).await.unwrap();
        assert_eq!(entry.message.answers[0].ttl, 120);
    }

    #[tokio::test]
    async fn negative_answers_use_configured_nx() {
        let cache = DnsCache::new(300, 600);
        let key = CacheKey {
            name: "example.com.".into(),
            query_type: 1,
            query_class: 1,
            dnssec_ok: false,
            checking_disabled: false,
        };
        // The SOA says 60 seconds, but the configured nx value wins.
        let mut response = negative_response(60, 3600);
        assert_eq!(cache.insert(key.clone(), &mut response).await, Some(600));
        let entry = cache.get(&key).await.unwrap();
        let soa_ttl = entry
            .message
            .authorities
            .iter()
            .find_map(|record| match &record.data {
                RData::SOA(_) => Some(record.ttl),
                _ => None,
            });
        assert_eq!(soa_ttl, Some(600));
    }

    #[tokio::test]
    async fn does_not_cache_zero_ttl() {
        let cache = DnsCache::new(300, 60);
        let key = CacheKey {
            name: "example.com.".into(),
            query_type: 1,
            query_class: 1,
            dnssec_ok: false,
            checking_disabled: false,
        };
        let mut response = positive_response(0);
        assert_eq!(cache.insert(key.clone(), &mut response).await, None);
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn does_not_cache_zero_soa_minimum() {
        let cache = DnsCache::new(300, 60);
        let key = CacheKey {
            name: "example.com.".into(),
            query_type: 1,
            query_class: 1,
            dnssec_ok: false,
            checking_disabled: false,
        };
        let mut response = negative_response(0, 3600);
        assert_eq!(cache.insert(key.clone(), &mut response).await, None);
        assert!(cache.get(&key).await.is_none());
    }

    fn cache_key(name: &str) -> CacheKey {
        CacheKey {
            name: name.into(),
            query_type: 1,
            query_class: 1,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    #[tokio::test]
    async fn purges_a_domain_subtree() {
        let cache = DnsCache::new(300, 60);
        for name in [
            "example.com.",
            "www.example.com.",
            "deep.www.example.com.",
            "notexample.com.",
            "other.test.",
        ] {
            let mut response = positive_response(120);
            cache.insert(cache_key(name), &mut response).await.unwrap();
        }

        assert_eq!(cache.purge_domain("example.com").await, 3);
        assert!(cache.get(&cache_key("example.com.")).await.is_none());
        assert!(cache.get(&cache_key("www.example.com.")).await.is_none());
        assert!(cache.get(&cache_key("notexample.com.")).await.is_some());

        assert_eq!(cache.purge_all().await, 2);
        assert!(cache.get(&cache_key("other.test.")).await.is_none());
    }

    #[tokio::test]
    async fn purges_snapshot_files() {
        let dir = std::env::temp_dir().join(format!(
            "dnscacher-purge-{}-{}",
            std::process::id(),
            SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.bin");

        let cache = DnsCache::new(300, 60);
        for name in ["one.example.com.", "two.example.com.", "other.test."] {
            let mut response = positive_response(120);
            cache.insert(cache_key(name), &mut response).await.unwrap();
        }
        cache.save_to(&path).await.unwrap();

        assert_eq!(purge_snapshot_file(&path, Some("example.com")).unwrap(), 2);
        let remaining = read_snapshot(&path).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0.name, "other.test.");

        assert_eq!(purge_snapshot_file(&path, None).unwrap(), 1);
        assert!(read_snapshot(&path).unwrap().is_empty());

        std::fs::remove_file(&path).unwrap();
        assert_eq!(purge_snapshot_file(&path, None).unwrap(), 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn normalizes_purge_domains() {
        assert_eq!(
            normalize_purge_domain(" Example.COM. ").unwrap(),
            "example.com"
        );
        assert!(normalize_purge_domain("").is_err());
        assert!(normalize_purge_domain("*.example.com").is_err());
        assert!(normalize_purge_domain("bad name").is_err());
    }

    fn negative_response(soa_minimum: u32, soa_ttl: u32) -> Message {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.response_code = ResponseCode::NXDomain;
        message.metadata.recursion_available = true;
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        message.add_authority(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            soa_ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.com.").unwrap(),
                Name::from_ascii("hostmaster.example.com.").unwrap(),
                1,
                3600,
                600,
                86400,
                soa_minimum,
            )),
        ));
        message
    }
}

#[cfg(test)]
mod postcard_roundtrip_tests {
    use super::*;

    #[test]
    fn disk_cache_roundtrips() {
        let disk = DiskCache {
            version: CACHE_VERSION,
            entries: vec![DiskEntry {
                key: CacheKey {
                    name: "example.com.".into(),
                    query_type: 1,
                    query_class: 1,
                    dnssec_ok: false,
                    checking_disabled: false,
                },
                wire: vec![0, 1, 2, 3],
                stored_at: 1,
                expires_at: 2,
                negative: false,
            }],
        };
        let bytes = postcard::to_stdvec(&disk).unwrap();
        let (decoded, remainder): (DiskCache, &[u8]) = postcard::take_from_bytes(&bytes).unwrap();
        assert!(remainder.is_empty());
        assert_eq!(decoded.version, disk.version);
        assert_eq!(decoded.entries.len(), 1);
    }
}
