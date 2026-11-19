//! Upstream transports and failover logic.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use rand::seq::SliceRandom;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{lookup_host, TcpStream, UdpSocket},
    task::JoinSet,
};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use tracing::{debug, warn};
use url::Url;

use crate::config::{Config, DnssecMode, Priority, Transport, Upstream};

const UPSTREAM_EDNS_PAYLOAD: u16 = 1232;
const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

pub struct Resolver {
    upstreams: Vec<Upstream>,
    priority: Priority,
    dnssec: DnssecMode,
    timeout: Duration,
    doh: DohClients,
    tls: TlsConnector,
    round_robin: AtomicUsize,
}

/// Reqwest clients used for DoH.  Tables that list plain addresses next to a
/// DoH hostname get a client that resolves that hostname to those addresses;
/// `fallback` uses the system resolver when the hints do not work.
#[derive(Clone)]
struct DohClients {
    fallback: reqwest::Client,
    hinted: HashMap<String, reqwest::Client>,
}

fn http_client(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(timeout)
        .pool_max_idle_per_host(8)
        .user_agent(concat!("dnscacher/", env!("CARGO_PKG_VERSION")))
}

fn doh_key(host: &str, hints: &[IpAddr]) -> String {
    let mut key = host.to_ascii_lowercase();
    for hint in hints {
        key.push('|');
        key.push_str(&hint.to_string());
    }
    key
}

/// A successful upstream exchange together with the endpoint that produced it.
#[derive(Debug, Clone)]
pub struct ResolvedAnswer {
    pub response: Message,
    pub upstream: Upstream,
}

impl Resolver {
    pub fn new(config: &Config) -> Result<Self> {
        let upstreams = config.dns.build_upstreams()?;
        let timeout = config.dns.timeout_duration();

        let fallback = http_client(timeout)
            .build()
            .context("failed to create HTTP client")?;

        let mut hinted = HashMap::new();
        for upstream in &upstreams {
            let Transport::Doh { url, hints } = &upstream.transport else {
                continue;
            };
            if hints.is_empty() {
                continue;
            }
            let Some(host) = url.host_str() else {
                continue;
            };
            // An IP literal needs no mapping; reqwest connects to it directly.
            if host.parse::<IpAddr>().is_ok() {
                continue;
            }

            let key = doh_key(host, hints);
            if hinted.contains_key(&key) {
                continue;
            }

            let port = url.port_or_known_default().unwrap_or(443);
            let addresses: Vec<SocketAddr> = hints
                .iter()
                .map(|address| SocketAddr::new(*address, port))
                .collect();
            let client = http_client(timeout)
                .resolve_to_addrs(host, &addresses)
                .build()
                .with_context(|| format!("failed to create HTTP client for {host}"))?;
            hinted.insert(key, client);
        }

        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let tls_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("failed to configure TLS")?
            .with_root_certificates(roots)
            .with_no_client_auth();

        Ok(Self {
            upstreams,
            priority: config.dns.priority,
            dnssec: config.dns.dnssec,
            timeout,
            doh: DohClients { fallback, hinted },
            tls: TlsConnector::from(Arc::new(tls_config)),
            round_robin: AtomicUsize::new(0),
        })
    }

    /// Forward a client query upstream according to the configured priority
    /// and domain rules.
    pub async fn resolve(
        &self,
        client_query: &Message,
        client_dnssec_ok: bool,
    ) -> Result<ResolvedAnswer> {
        let query = upstream_query(client_query, self.dnssec, client_dnssec_ok);
        let name = query
            .queries
            .first()
            .map(|query| query.name.to_lowercase().to_ascii())
            .unwrap_or_default();

        let specific: Vec<&Upstream> = self
            .upstreams
            .iter()
            .filter(|upstream| upstream.is_domain_specific() && upstream.applies_to(&name))
            .collect();

        let candidates: Vec<&Upstream> = if specific.is_empty() {
            self.upstreams
                .iter()
                .filter(|upstream| !upstream.is_domain_specific())
                .collect()
        } else {
            specific
        };

        if candidates.is_empty() {
            bail!("no upstream is configured for {name}");
        }

        match self.priority {
            Priority::All => self.resolve_all(&query, candidates).await,
            Priority::Order => self.resolve_sequential(&query, candidates).await,
            Priority::RoundRobin => {
                let start = self.round_robin.fetch_add(1, Ordering::Relaxed);
                let mut rotated = candidates;
                if !rotated.is_empty() {
                    let length = rotated.len();
                    rotated.rotate_left(start % length);
                }
                self.resolve_sequential(&query, rotated).await
            }
            Priority::Random => {
                let mut shuffled = candidates;
                shuffled.shuffle(&mut rand::thread_rng());
                self.resolve_sequential(&query, shuffled).await
            }
        }
    }

    async fn resolve_sequential(
        &self,
        query: &Message,
        candidates: Vec<&Upstream>,
    ) -> Result<ResolvedAnswer> {
        let mut errors = Vec::new();
        let mut last_retryable = None;

        for upstream in candidates {
            match exchange(upstream, query, self.timeout, &self.doh, &self.tls).await {
                Ok(response) => {
                    if retryable_response(&response) {
                        warn!(
                            upstream = %upstream.table,
                            response = ?response.metadata.response_code,
                            "upstream returned a retryable response"
                        );
                        last_retryable = Some((response, upstream.clone()));
                    } else {
                        return Ok(ResolvedAnswer {
                            response,
                            upstream: upstream.clone(),
                        });
                    }
                }
                Err(error) => {
                    debug!(
                        upstream = %upstream.table,
                        transport = ?upstream.transport,
                        %error,
                        "upstream attempt failed"
                    );
                    errors.push(format!("{}: {error:#}", upstream.table));
                }
            }
        }

        if let Some((response, upstream)) = last_retryable {
            return Ok(ResolvedAnswer { response, upstream });
        }

        bail!("all upstream attempts failed: {}", errors.join("; "))
    }

    async fn resolve_all(
        &self,
        query: &Message,
        candidates: Vec<&Upstream>,
    ) -> Result<ResolvedAnswer> {
        let mut tasks = JoinSet::new();
        let mut errors = Vec::new();

        for upstream in candidates {
            let upstream = upstream.clone();
            let query = query.clone();
            let doh = self.doh.clone();
            let tls = self.tls.clone();
            let timeout = self.timeout;
            tasks.spawn(async move {
                let response = exchange(&upstream, &query, timeout, &doh, &tls).await;
                (upstream, response)
            });
        }

        let mut last_retryable = None;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((upstream, Ok(response))) => {
                    if retryable_response(&response) {
                        last_retryable = Some((response, upstream));
                    } else {
                        tasks.abort_all();
                        return Ok(ResolvedAnswer { response, upstream });
                    }
                }
                Ok((upstream, Err(error))) => {
                    debug!(
                        upstream = %upstream.table,
                        transport = ?upstream.transport,
                        %error,
                        "upstream attempt failed"
                    );
                    errors.push(format!("{}: {error:#}", upstream.table));
                }
                Err(error) => errors.push(format!("upstream task failed: {error}")),
            }
        }

        if let Some((response, upstream)) = last_retryable {
            return Ok(ResolvedAnswer { response, upstream });
        }

        bail!("all upstream attempts failed: {}", errors.join("; "))
    }
}

async fn exchange(
    upstream: &Upstream,
    query: &Message,
    timeout: Duration,
    doh: &DohClients,
    tls: &TlsConnector,
) -> Result<Message> {
    let wire = query.to_vec().context("failed to encode upstream query")?;
    if wire.len() > MAX_DNS_MESSAGE {
        bail!("upstream query is too large");
    }

    let raw = tokio::time::timeout(timeout, async {
        match &upstream.transport {
            Transport::Udp { address } => exchange_udp(*address, &wire).await,
            Transport::Dot { host, port, hints } => {
                exchange_dot(tls, host, *port, hints, &wire).await
            }
            Transport::Doh { url, hints } => exchange_doh(doh, url, hints, &wire).await,
        }
    })
    .await
    .context("upstream attempt timed out")??;

    if raw.len() > MAX_DNS_MESSAGE {
        bail!("upstream response is too large");
    }

    let response =
        Message::from_vec(&raw).context("upstream returned an unparsable DNS message")?;
    validate_response(query, &response)?;
    Ok(response)
}

async fn exchange_udp(address: SocketAddr, wire: &[u8]) -> Result<Vec<u8>> {
    let bind_address = match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::from([0u16; 8]), 0),
    };
    let socket = UdpSocket::bind(bind_address)
        .await
        .context("failed to bind UDP socket")?;
    socket
        .connect(address)
        .await
        .context("failed to connect UDP socket")?;
    socket
        .send(wire)
        .await
        .context("failed to send UDP query")?;

    let mut buffer = vec![0u8; MAX_DNS_MESSAGE];
    let read = socket
        .recv(&mut buffer)
        .await
        .context("failed to receive UDP response")?;
    buffer.truncate(read);

    // A truncated UDP response must be retried over TCP.
    let truncated = Message::from_vec(&buffer)
        .map(|message| message.metadata.truncation)
        .unwrap_or(false);
    if truncated {
        return exchange_tcp(address, wire).await;
    }

    Ok(buffer)
}

async fn exchange_tcp(address: SocketAddr, wire: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address)
        .await
        .with_context(|| format!("failed to connect to {address}"))?;
    stream.set_nodelay(true).ok();
    write_frame(&mut stream, wire).await?;
    read_frame(&mut stream).await
}

async fn exchange_dot(
    connector: &TlsConnector,
    host: &str,
    port: u16,
    hints: &[IpAddr],
    wire: &[u8],
) -> Result<Vec<u8>> {
    let literal = host.parse::<IpAddr>().ok();
    let mut attempts: Vec<SocketAddr> = Vec::new();

    if let Some(address) = literal {
        attempts.push(SocketAddr::new(address, port));
    } else {
        // The plain addresses in this table are the expected addresses of the
        // DoT hostname; try them before asking the system resolver.
        for hint in hints {
            let address = SocketAddr::new(*hint, port);
            if !attempts.contains(&address) {
                attempts.push(address);
            }
        }
    }

    let mut last_error = None;
    for address in &attempts {
        match exchange_dot_at(connector, host, *address, wire).await {
            Ok(raw) => return Ok(raw),
            Err(error) => last_error = Some(error),
        }
    }

    if literal.is_some() {
        return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("DoT host {host} is unusable")));
    }

    debug!(
        host = %host,
        error = ?last_error,
        "hinted DoT addresses failed, falling back to system resolution"
    );

    // Fall back to the system resolver, for example when the plain addresses
    // in the same table belong to a different provider.
    let resolved = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve DoT host {host}"))?;
    for address in resolved {
        if attempts.contains(&address) {
            continue;
        }
        match exchange_dot_at(connector, host, address, wire).await {
            Ok(raw) => return Ok(raw),
            Err(error) => {
                debug!(host = %host, %address, %error, "DoT address failed");
                last_error = Some(error);
            }
        }
    }

    if let Some(error) = last_error {
        return Err(error);
    }
    bail!("DoT host {host} has no address")
}

async fn exchange_dot_at(
    connector: &TlsConnector,
    host: &str,
    address: SocketAddr,
    wire: &[u8],
) -> Result<Vec<u8>> {
    let stream = TcpStream::connect(address)
        .await
        .with_context(|| format!("failed to connect to DoT server {address}"))?;
    stream.set_nodelay(true).ok();

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid DoT server name {host:?}"))?;
    let mut stream = connector
        .connect(server_name, stream)
        .await
        .with_context(|| format!("DoT handshake with {host} ({address}) failed"))?;

    write_frame(&mut stream, wire).await?;
    read_frame(&mut stream).await
}

async fn exchange_doh(
    clients: &DohClients,
    url: &Url,
    hints: &[IpAddr],
    wire: &[u8],
) -> Result<Vec<u8>> {
    if !hints.is_empty() {
        if let Some(host) = url.host_str() {
            if host.parse::<IpAddr>().is_err() {
                if let Some(client) = clients.hinted.get(&doh_key(host, hints)) {
                    match doh_request(client, url, wire).await {
                        Ok(raw) => return Ok(raw),
                        Err(error) => debug!(
                            host = %host,
                            %error,
                            "hinted DoH addresses failed, falling back to system resolution"
                        ),
                    }
                }
            }
        }
    }

    doh_request(&clients.fallback, url, wire).await
}

async fn doh_request(http: &reqwest::Client, url: &Url, wire: &[u8]) -> Result<Vec<u8>> {
    let response = http
        .post(url.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(wire.to_vec())
        .send()
        .await
        .with_context(|| format!("DoH request to {url} failed"))?;

    let status = response.status();
    if !status.is_success() {
        bail!("DoH server {url} returned HTTP {status}");
    }

    let body = response
        .bytes()
        .await
        .with_context(|| format!("failed to read DoH response from {url}"))?;
    if body.len() > MAX_DNS_MESSAGE {
        bail!("DoH response from {url} is too large");
    }
    Ok(body.to_vec())
}

async fn write_frame<W>(writer: &mut W, wire: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if wire.len() > MAX_DNS_MESSAGE {
        bail!("DNS message is too large for TCP framing");
    }
    writer
        .write_all(&(wire.len() as u16).to_be_bytes())
        .await
        .context("failed to write TCP frame length")?;
    writer
        .write_all(wire)
        .await
        .context("failed to write TCP frame")?;
    writer.flush().await.context("failed to flush TCP frame")?;
    Ok(())
}

async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    reader
        .read_exact(&mut length)
        .await
        .context("failed to read TCP frame length")?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        bail!("received an empty TCP frame");
    }

    let mut buffer = vec![0u8; length];
    reader
        .read_exact(&mut buffer)
        .await
        .context("failed to read TCP frame")?;
    Ok(buffer)
}

fn upstream_query(client_query: &Message, dnssec: DnssecMode, client_dnssec_ok: bool) -> Message {
    let mut query = client_query.clone();
    query.metadata.id = rand::random();
    query.metadata.message_type = MessageType::Query;
    query.metadata.authoritative = false;
    query.metadata.truncation = false;
    query.metadata.recursion_available = false;
    query.metadata.recursion_desired = true;
    query.metadata.authentic_data = false;
    query.answers.clear();
    query.authorities.clear();
    query.additionals.clear();

    let dnssec_ok = match dnssec {
        DnssecMode::Off => false,
        DnssecMode::Allow => client_dnssec_ok,
        DnssecMode::Enforce => true,
    };

    // Client EDNS options are intentionally not forwarded; a fresh OPT record
    // avoids leaking client-specific options into a shared cache.
    let mut edns = Edns::new();
    edns.set_max_payload(UPSTREAM_EDNS_PAYLOAD);
    edns.set_dnssec_ok(dnssec_ok);
    query.set_edns(edns);

    query
}

fn validate_response(query: &Message, response: &Message) -> Result<()> {
    if response.metadata.id != query.metadata.id {
        bail!(
            "upstream response ID mismatch ({} != {})",
            response.metadata.id,
            query.metadata.id
        );
    }
    if response.metadata.message_type != MessageType::Response {
        bail!("upstream message is not a response");
    }
    if response.metadata.op_code != query.metadata.op_code {
        bail!("upstream response opcode mismatch");
    }
    if response.queries.len() != query.queries.len() {
        bail!("upstream response question count mismatch");
    }

    for (got, expected) in response.queries.iter().zip(query.queries.iter()) {
        if got.name != expected.name
            || got.query_type != expected.query_type
            || got.query_class != expected.query_class
        {
            bail!("upstream response question mismatch");
        }
    }

    Ok(())
}

fn retryable_response(response: &Message) -> bool {
    matches!(
        response.metadata.response_code,
        ResponseCode::ServFail
            | ResponseCode::Refused
            | ResponseCode::NotImp
            | ResponseCode::FormErr
    )
}
