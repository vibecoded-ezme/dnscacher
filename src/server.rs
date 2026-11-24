//! UDP/TCP DNS front-end and request processing.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use bytes::Bytes;
use hickory_proto::{
    op::{Edns, Message, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA, CNAME, PTR, SOA},
        DNSClass, Name, RData, Record, RecordType,
    },
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming,
    header::{ALLOW, CONTENT_TYPE},
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as HttpBuilder,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{watch, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, trace, warn};

use crate::{
    cache::{now_unix, CacheKey, DnsCache},
    config::{DenyMode, DnssecMode, ServerConfig as ServerSettings},
    hosts::{Addresses, HostsStore},
    rules::{Rewrite, RulesStore},
    upstream::{ResolvedAnswer, Resolver},
};

const HOSTS_TTL: u32 = 60;
const DENY_TTL: u32 = 60;
const REWRITE_TTL: u32 = 60;
const MAX_REWRITE_DEPTH: usize = 8;
const SERVER_EDNS_PAYLOAD: u16 = 1232;
const MAX_UDP_PAYLOAD: u16 = 4096;
const MAX_UDP_IN_FLIGHT: usize = 1024;
const MAX_TCP_CONNECTIONS: usize = 1024;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DOT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DOH_MAX_BODY: usize = u16::MAX as usize;
const DNS_MESSAGE_MEDIA_TYPE: &str = "application/dns-message";

pub struct AppState {
    pub cache: Arc<DnsCache>,
    pub resolver: Resolver,
    pub hosts: HostsStore,
    pub rules: RulesStore,
    pub dnssec: DnssecMode,
    pub deny: DenyMode,
}

/// Bind every configured address and start serving.  Returns the tasks so the
/// caller can abort them during shutdown.
pub async fn start(
    state: Arc<AppState>,
    settings: &ServerSettings,
    shutdown: watch::Receiver<bool>,
) -> Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    let mut bound_plain = false;

    for address in &settings.address {
        let socket_address = SocketAddr::new(*address, settings.port);

        match UdpSocket::bind(socket_address).await {
            Ok(socket) => {
                bound_plain = true;
                info!(%socket_address, "listening on UDP");
                handles.push(tokio::spawn(udp_loop(
                    state.clone(),
                    Arc::new(socket),
                    shutdown.clone(),
                )));
            }
            Err(error) => {
                warn!(%socket_address, %error, "failed to bind UDP socket");
            }
        }

        match TcpListener::bind(socket_address).await {
            Ok(listener) => {
                bound_plain = true;
                info!(%socket_address, "listening on TCP");
                handles.push(tokio::spawn(tcp_loop(
                    state.clone(),
                    listener,
                    shutdown.clone(),
                )));
            }
            Err(error) => {
                warn!(%socket_address, %error, "failed to bind TCP listener");
            }
        }
    }

    if !bound_plain {
        bail!(
            "failed to bind any server address on port {} (are you root? try --port 5353)",
            settings.port
        );
    }

    if let Some(dot) = &settings.dot {
        let acceptor = TlsAcceptor::from(crate::tls::load_server_config(&dot.cert, &dot.key, &[])?);
        let mut bound_dot = false;
        for address in dot.listen_addresses(settings) {
            let socket_address = SocketAddr::new(*address, dot.port);
            match TcpListener::bind(socket_address).await {
                Ok(listener) => {
                    bound_dot = true;
                    info!(%socket_address, "listening on DNS over TLS");
                    handles.push(tokio::spawn(dot_loop(
                        state.clone(),
                        listener,
                        acceptor.clone(),
                        shutdown.clone(),
                    )));
                }
                Err(error) => {
                    warn!(%socket_address, %error, "failed to bind DoT listener");
                }
            }
        }
        if !bound_dot {
            bail!("failed to bind any DoT listener on port {}", dot.port);
        }
    }

    if let Some(doh) = &settings.doh {
        let acceptor = TlsAcceptor::from(crate::tls::load_server_config(
            &doh.cert,
            &doh.key,
            &[b"h2", b"http/1.1"],
        )?);
        let path = Arc::<str>::from(doh.path.as_str());
        let mut bound_doh = false;
        for address in doh.listen_addresses(settings) {
            let socket_address = SocketAddr::new(*address, doh.port);
            match TcpListener::bind(socket_address).await {
                Ok(listener) => {
                    bound_doh = true;
                    info!(%socket_address, path = %path, "listening on DNS over HTTPS");
                    handles.push(tokio::spawn(doh_loop(
                        state.clone(),
                        listener,
                        acceptor.clone(),
                        path.clone(),
                        shutdown.clone(),
                    )));
                }
                Err(error) => {
                    warn!(%socket_address, %error, "failed to bind DoH listener");
                }
            }
        }
        if !bound_doh {
            bail!("failed to bind any DoH listener on port {}", doh.port);
        }
    }

    Ok(handles)
}

async fn udp_loop(
    state: Arc<AppState>,
    socket: Arc<UdpSocket>,
    mut shutdown: watch::Receiver<bool>,
) {
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    let mut buffer = vec![0u8; usize::from(u16::MAX)];

    loop {
        tokio::select! {
            _ = shutdown_requested(&mut shutdown) => break,
            result = socket.recv_from(&mut buffer) => {
                let (length, peer) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(%error, "UDP receive failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                let permit = match in_flight.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%peer, "dropping UDP query: too many in-flight queries");
                        continue;
                    }
                };

                let query = buffer[..length].to_vec();
                let state = state.clone();
                let socket = socket.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(response) = handle(&state, &query, peer, true).await {
                        if let Err(error) = socket.send_to(&response, peer).await {
                            debug!(%peer, %error, "failed to send UDP response");
                        }
                    }
                });
            }
        }
    }
}

async fn tcp_loop(
    state: Arc<AppState>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));

    loop {
        tokio::select! {
            _ = shutdown_requested(&mut shutdown) => break,
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(%error, "TCP accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%peer, "dropping TCP connection: too many connections");
                        continue;
                    }
                };

                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    stream.set_nodelay(true).ok();
                    handle_tcp_connection(state, stream, peer, TCP_IDLE_TIMEOUT).await;
                });
            }
        }
    }
}

async fn dot_loop(
    state: Arc<AppState>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    mut shutdown: watch::Receiver<bool>,
) {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));

    loop {
        tokio::select! {
            _ = shutdown_requested(&mut shutdown) => break,
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(%error, "DoT accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%peer, "dropping DoT connection: too many connections");
                        continue;
                    }
                };

                let state = state.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    stream.set_nodelay(true).ok();
                    match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            handle_tcp_connection(state, stream, peer, DOT_IDLE_TIMEOUT).await;
                        }
                        Ok(Err(error)) => debug!(%peer, %error, "DoT handshake failed"),
                        Err(_) => debug!(%peer, "DoT handshake timed out"),
                    }
                });
            }
        }
    }
}

async fn doh_loop(
    state: Arc<AppState>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    path: Arc<str>,
    mut shutdown: watch::Receiver<bool>,
) {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));

    loop {
        tokio::select! {
            _ = shutdown_requested(&mut shutdown) => break,
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        warn!(%error, "DoH accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%peer, "dropping DoH connection: too many connections");
                        continue;
                    }
                };

                let state = state.clone();
                let acceptor = acceptor.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    stream.set_nodelay(true).ok();
                    let stream = match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => {
                            debug!(%peer, %error, "DoH handshake failed");
                            return;
                        }
                        Err(_) => {
                            debug!(%peer, "DoH handshake timed out");
                            return;
                        }
                    };

                    let service = service_fn(move |request: Request<Incoming>| {
                        let state = state.clone();
                        let path = path.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                doh_request(&state, peer, &path, request).await,
                            )
                        }
                    });

                    let builder = HttpBuilder::new(TokioExecutor::new());
                    if let Err(error) = builder
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        debug!(%peer, %error, "DoH connection failed");
                    }
                });
            }
        }
    }
}

async fn doh_request(
    state: &AppState,
    peer: SocketAddr,
    path: &str,
    request: Request<Incoming>,
) -> Response<Full<Bytes>> {
    if request.uri().path() != path {
        return http_text(StatusCode::NOT_FOUND, "not found");
    }

    let wire = match *request.method() {
        Method::POST => {
            if !is_dns_message_content_type(&request) {
                return http_text(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "expected Content-Type: application/dns-message",
                );
            }
            let body = request.into_body();
            match Limited::new(body, DOH_MAX_BODY).collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(error) if error.is::<http_body_util::LengthLimitError>() => {
                    return http_text(StatusCode::PAYLOAD_TOO_LARGE, "DNS message too large");
                }
                Err(error) => {
                    debug!(%peer, %error, "failed to read DoH request body");
                    return http_text(StatusCode::BAD_REQUEST, "failed to read request body");
                }
            }
        }
        Method::GET => {
            let Some(encoded) = query_parameter(request.uri(), "dns") else {
                return http_text(StatusCode::BAD_REQUEST, "missing dns query parameter");
            };
            match decode_dns_parameter(&encoded) {
                Some(wire) => wire,
                None => return http_text(StatusCode::BAD_REQUEST, "invalid dns query parameter"),
            }
        }
        _ => {
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(ALLOW, "GET, POST")
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Full::new(Bytes::from_static(b"method not allowed\n")))
                .expect("valid response");
        }
    };

    if wire.is_empty() {
        return http_text(StatusCode::BAD_REQUEST, "empty DNS message");
    }

    match handle(state, &wire, peer, false).await {
        Some(response) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, DNS_MESSAGE_MEDIA_TYPE)
            .body(Full::new(Bytes::from(response)))
            .expect("valid response"),
        None => http_text(StatusCode::BAD_REQUEST, "not a DNS query"),
    }
}

fn http_text(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!("{message}\n"))))
        .expect("valid response")
}

fn is_dns_message_content_type(request: &Request<Incoming>) -> bool {
    request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().eq_ignore_ascii_case(DNS_MESSAGE_MEDIA_TYPE))
        .unwrap_or(false)
}

fn query_parameter(uri: &hyper::Uri, name: &str) -> Option<String> {
    for pair in uri.query()?.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == name {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                decoded.push((high * 16 + low) as u8);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn decode_dns_parameter(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

async fn handle_tcp_connection<S>(
    state: Arc<AppState>,
    mut stream: S,
    peer: SocketAddr,
    idle: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    trace!(%peer, "TCP connection opened");

    loop {
        let frame = match timeout(idle, read_tcp_message(&mut stream)).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => break,
            Ok(Err(error)) => {
                debug!(%peer, %error, "failed to read TCP query");
                break;
            }
            Err(_) => {
                debug!(%peer, "closing idle TCP connection");
                break;
            }
        };

        let Some(response) = handle(&state, &frame, peer, false).await else {
            break;
        };
        if response.len() > usize::from(u16::MAX) {
            warn!(%peer, "response too large for TCP");
            break;
        }

        if let Err(error) = write_tcp_message(&mut stream, &response).await {
            debug!(%peer, %error, "failed to write TCP response");
            break;
        }
    }

    trace!(%peer, "TCP connection closed");
}

async fn read_tcp_message<S>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let mut length = [0u8; 2];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }

    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 {
        return Ok(None);
    }

    let mut frame = vec![0u8; length];
    stream.read_exact(&mut frame).await?;
    Ok(Some(frame))
}

async fn write_tcp_message<S>(stream: &mut S, response: &[u8]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&(response.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(response).await?;
    stream.flush().await
}

/// Process a raw DNS message.  Returns the encoded response, or `None` when
/// the input is not a query and should be ignored.
async fn handle(state: &AppState, wire: &[u8], peer: SocketAddr, udp: bool) -> Option<Vec<u8>> {
    let request = match Message::from_vec(wire) {
        Ok(request) => request,
        Err(error) => {
            debug!(%peer, %error, "dropping malformed DNS message");
            return form_error(wire);
        }
    };

    if request.metadata.message_type != hickory_proto::op::MessageType::Query {
        trace!(%peer, "ignoring non-query message");
        return None;
    }

    let response = process(state, &request, peer).await;
    let client_edns = request.edns.clone();
    let byte_limit = if udp {
        client_edns
            .as_ref()
            .map(|edns| edns.max_payload())
            .unwrap_or(512)
            .clamp(512, MAX_UDP_PAYLOAD)
    } else {
        u16::MAX
    };

    let mut encoded = match response.to_vec() {
        Ok(encoded) => encoded,
        Err(error) => {
            warn!(%peer, %error, "failed to encode DNS response");
            return None;
        }
    };

    if udp && encoded.len() > usize::from(byte_limit) {
        let truncated = response.truncate();
        encoded = match truncated.to_vec() {
            Ok(encoded) => encoded,
            Err(error) => {
                warn!(%peer, %error, "failed to encode truncated DNS response");
                return None;
            }
        };
        if encoded.len() > usize::from(byte_limit) {
            warn!(%peer, bytes = encoded.len(), limit = byte_limit, "truncated response still exceeds client payload limit");
        }
    }

    Some(encoded)
}

async fn process(state: &AppState, request: &Message, peer: SocketAddr) -> Message {
    if request.metadata.op_code != OpCode::Query {
        return error_response(request, ResponseCode::NotImp);
    }
    if request.queries.len() != 1 {
        return error_response(request, ResponseCode::FormErr);
    }

    let query = &request.queries[0];
    let query_name = query.name.to_lowercase().to_ascii();
    let query_type = query.query_type;
    let client_dnssec_ok = request
        .edns
        .as_ref()
        .map(|edns| edns.flags().dnssec_ok)
        .unwrap_or(false);

    if query.query_class != DNSClass::IN {
        return error_response(request, ResponseCode::NotImp);
    }

    // Local hosts records always win over rewrites, the cache and upstreams.
    let hosts = state.hosts.get();
    if let Some(addresses) = hosts.lookup(&query_name) {
        debug!(%peer, name = %query_name, ?query_type, "answered from hosts file");
        return local_address_response(request, &addresses, query_type);
    }

    if query_type == RecordType::PTR {
        if let Some(hostname) = hosts.lookup_ptr(&query_name) {
            debug!(%peer, name = %query_name, "answered reverse lookup from hosts file");
            return ptr_response(request, &hostname);
        }
    }

    let dnssec_ok = match state.dnssec {
        DnssecMode::Off => false,
        DnssecMode::Allow => client_dnssec_ok,
        DnssecMode::Enforce => true,
    };

    let Some(cache_key) = CacheKey::from_query(request, dnssec_ok) else {
        return error_response(request, ResponseCode::FormErr);
    };

    // Rewrite rules are explicit user policy, so they outrank deny entries.
    let rules = state.rules.get();
    if let Some(rewrite) = rules.rewrite(&query_name, query_type) {
        return rewritten_response(state, request, peer, rewrite, &cache_key, client_dnssec_ok)
            .await;
    }

    if let Some(address) = hosts.denied(&query_name) {
        debug!(%peer, name = %query_name, "domain matched deny list");
        return deny_response(request, state.deny, query_type, address);
    }

    if let Some(entry) = state.cache.get(&cache_key).await {
        let age = now_unix().saturating_sub(entry.stored_at);
        let age = u32::try_from(age).unwrap_or(u32::MAX);
        let mut response = entry.message;
        decrement_ttls(&mut response, age);
        finalize_response(request, &mut response, state.dnssec);
        debug!(
            %peer,
            name = %query_name,
            ?query_type,
            age,
            negative = entry.negative,
            "cache hit"
        );
        return response;
    }

    match state.resolver.resolve(request, client_dnssec_ok).await {
        Ok(answer) => {
            let ResolvedAnswer {
                mut response,
                upstream,
            } = answer;

            if state.dnssec == DnssecMode::Enforce
                && !request.metadata.checking_disabled
                && !response.metadata.authentic_data
            {
                warn!(
                    %peer,
                    name = %query_name,
                    ?query_type,
                    upstream_table = %upstream.table,
                    "DNSSEC enforcement failed: upstream did not validate the answer"
                );
                return error_response(request, ResponseCode::ServFail);
            }

            if apply_null_answer_policy(request, &mut response, state.deny) {
                debug!(
                    %peer,
                    name = %query_name,
                    ?query_type,
                    deny = ?state.deny,
                    upstream_table = %upstream.table,
                    "rewrote null upstream answer using deny policy"
                );
            }

            let ttl = state.cache.insert(cache_key, &mut response).await;
            debug!(
                %peer,
                name = %query_name,
                ?query_type,
                upstream_table = %upstream.table,
                transport = ?upstream.transport,
                rcode = ?response.metadata.response_code,
                ttl = ttl.unwrap_or(0),
                cached = ttl.is_some(),
                "upstream response"
            );
            finalize_response(request, &mut response, state.dnssec);
            response
        }
        Err(error) => {
            warn!(
                %peer,
                name = %query_name,
                ?query_type,
                %error,
                "upstream resolution failed"
            );
            error_response(request, ResponseCode::ServFail)
        }
    }
}

enum DirectRewrite {
    Rcode(ResponseCode),
    Records(Vec<RData>),
}

/// Answer a query that matched one or more `$dnsrewrite` rules.  A CNAME
/// rewrite follows the local rule chain and then resolves the final target
/// through the normal upstream selection, so clients see the complete chain.
async fn rewritten_response(
    state: &AppState,
    request: &Message,
    peer: SocketAddr,
    initial: Rewrite,
    cache_key: &CacheKey,
    client_dnssec_ok: bool,
) -> Message {
    let query_type = request.queries[0].query_type;

    if initial.cname.is_none() {
        debug!(
            %peer,
            name = %request.queries[0].name,
            ?query_type,
            "answered from rewrite rule"
        );
        let direct = match initial.rcode {
            Some(code) => DirectRewrite::Rcode(code),
            None => DirectRewrite::Records(initial.records),
        };
        return direct_rewrite_response(request, &[], direct);
    }

    // A rewritten answer is cacheable like an upstream answer, using the
    // original query name as the key.
    if let Some(entry) = state.cache.get(cache_key).await {
        let age = now_unix().saturating_sub(entry.stored_at);
        let age = u32::try_from(age).unwrap_or(u32::MAX);
        let mut response = entry.message;
        decrement_ttls(&mut response, age);
        finalize_response(request, &mut response, state.dnssec);
        debug!(
            %peer,
            name = %request.queries[0].name,
            ?query_type,
            age,
            negative = entry.negative,
            "cache hit for rewritten name"
        );
        return response;
    }

    let rules = state.rules.get();
    let mut chain: Vec<(Name, Name)> = Vec::new();
    let mut current = request.queries[0].name.clone();
    let mut next = Some(initial);
    let mut direct = None;
    let mut visited = HashSet::new();
    let mut depth = 0usize;

    loop {
        depth += 1;
        if depth > MAX_REWRITE_DEPTH {
            warn!(
                %peer,
                name = %request.queries[0].name,
                "rewrite chain is too deep"
            );
            return error_response(request, ResponseCode::ServFail);
        }

        let Some(rewrite) = next.take() else {
            break;
        };
        if let Some(code) = rewrite.rcode {
            direct = Some(DirectRewrite::Rcode(code));
            break;
        }
        if let Some(target) = rewrite.cname {
            let label = current.to_ascii().to_ascii_lowercase();
            if !visited.insert(label) {
                warn!(
                    %peer,
                    name = %request.queries[0].name,
                    loop_at = %current,
                    "rewrite rule loop detected"
                );
                return error_response(request, ResponseCode::ServFail);
            }
            chain.push((current.clone(), target.clone()));
            current = target;
            let name = current.to_ascii().to_ascii_lowercase();
            next = rules.rewrite(&name, query_type);
            continue;
        }
        direct = Some(DirectRewrite::Records(rewrite.records));
        break;
    }

    if let Some(direct) = direct {
        debug!(
            %peer,
            name = %request.queries[0].name,
            ?query_type,
            hops = chain.len(),
            "answered from rewrite rule chain"
        );
        return direct_rewrite_response(request, &chain, direct);
    }

    let mut target_request = request.clone();
    target_request.queries[0].name = current.clone();

    match state
        .resolver
        .resolve(&target_request, client_dnssec_ok)
        .await
    {
        Ok(ResolvedAnswer {
            mut response,
            upstream,
        }) => {
            if state.dnssec == DnssecMode::Enforce
                && !request.metadata.checking_disabled
                && !response.metadata.authentic_data
            {
                warn!(
                    %peer,
                    name = %request.queries[0].name,
                    target = %current,
                    upstream_table = %upstream.table,
                    "DNSSEC enforcement failed for rewrite target"
                );
                return error_response(request, ResponseCode::ServFail);
            }

            let mut answers = Vec::with_capacity(chain.len() + response.answers.len());
            for (from, to) in &chain {
                answers.push(Record::from_rdata(
                    from.clone(),
                    REWRITE_TTL,
                    RData::CNAME(CNAME(to.clone())),
                ));
            }
            answers.append(&mut response.answers);
            response.answers = answers;
            // The synthesized CNAME hops are unsigned.
            response.metadata.authentic_data = false;

            if apply_null_answer_policy(request, &mut response, state.deny) {
                debug!(
                    %peer,
                    name = %request.queries[0].name,
                    target = %current,
                    deny = ?state.deny,
                    "rewrote null rewrite-target answer using deny policy"
                );
            }

            let ttl = state.cache.insert(cache_key.clone(), &mut response).await;
            debug!(
                %peer,
                name = %request.queries[0].name,
                ?query_type,
                target = %current,
                hops = chain.len(),
                upstream_table = %upstream.table,
                transport = ?upstream.transport,
                rcode = ?response.metadata.response_code,
                ttl = ttl.unwrap_or(0),
                cached = ttl.is_some(),
                "upstream response for rewritten name"
            );
            finalize_response(request, &mut response, state.dnssec);
            response
        }
        Err(error) => {
            warn!(
                %peer,
                name = %request.queries[0].name,
                target = %current,
                %error,
                "rewrite target resolution failed"
            );
            error_response(request, ResponseCode::ServFail)
        }
    }
}

fn direct_rewrite_response(
    client: &Message,
    chain: &[(Name, Name)],
    direct: DirectRewrite,
) -> Message {
    let mut response = base_response(client);
    response.metadata.authoritative = true;
    response.metadata.authentic_data = false;

    let terminal = chain
        .last()
        .map(|(_, target)| target.clone())
        .unwrap_or_else(|| client.queries[0].name.clone());

    for (from, target) in chain {
        response.add_answer(Record::from_rdata(
            from.clone(),
            REWRITE_TTL,
            RData::CNAME(CNAME(target.clone())),
        ));
    }
    let chain_answers = response.answers.len();

    match direct {
        DirectRewrite::Rcode(code) => {
            response.metadata.response_code = code;
            if matches!(code, ResponseCode::NXDomain | ResponseCode::NoError) {
                add_negative_soa(&mut response, REWRITE_TTL);
            }
        }
        DirectRewrite::Records(records) => {
            for value in records {
                response.add_answer(Record::from_rdata(terminal.clone(), REWRITE_TTL, value));
            }
            if response.answers.len() == chain_answers {
                add_negative_soa(&mut response, REWRITE_TTL);
            }
        }
    }

    response
}

fn finalize_response(client: &Message, response: &mut Message, dnssec: DnssecMode) {
    response.metadata.id = client.metadata.id;
    response.metadata.message_type = hickory_proto::op::MessageType::Response;
    response.metadata.op_code = client.metadata.op_code;
    response.metadata.recursion_desired = client.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.checking_disabled = client.metadata.checking_disabled;
    response.queries = client.queries.clone();

    let client_dnssec_ok = client
        .edns
        .as_ref()
        .map(|edns| edns.flags().dnssec_ok)
        .unwrap_or(false);

    // Responses without the DO bit must not contain DNSSEC records they did
    // not ask for.  This also removes validation material from cached answers
    // for plain clients.
    if dnssec == DnssecMode::Off || !client_dnssec_ok {
        *response = response.clone().maybe_strip_dnssec_records(false);
    }
    if dnssec == DnssecMode::Off {
        response.metadata.authentic_data = false;
    }

    let response_rcode_high = response
        .edns
        .as_ref()
        .map(|edns| edns.rcode_high())
        .unwrap_or(0);

    response.edns = client.edns.as_ref().map(|client_edns| {
        let mut edns = Edns::new();
        edns.set_max_payload(SERVER_EDNS_PAYLOAD);
        edns.set_dnssec_ok(client_edns.flags().dnssec_ok);
        edns.set_rcode_high(response_rcode_high);
        edns
    });
}

fn base_response(client: &Message) -> Message {
    let mut response = Message::response(client.metadata.id, client.metadata.op_code);
    response.metadata.recursion_desired = client.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.checking_disabled = client.metadata.checking_disabled;
    response.queries = client.queries.clone();
    response.edns = client.edns.as_ref().map(|client_edns| {
        let mut edns = Edns::new();
        edns.set_max_payload(SERVER_EDNS_PAYLOAD);
        edns.set_dnssec_ok(client_edns.flags().dnssec_ok);
        edns
    });
    response
}

fn error_response(client: &Message, response_code: ResponseCode) -> Message {
    let mut response = base_response(client);
    response.metadata.response_code = response_code;
    response
}

fn form_error(wire: &[u8]) -> Option<Vec<u8>> {
    if wire.len() < 2 {
        return None;
    }
    let id = u16::from_be_bytes([wire[0], wire[1]]);
    Message::error_msg(id, OpCode::Query, ResponseCode::FormErr)
        .to_vec()
        .ok()
}

fn local_address_response(
    client: &Message,
    addresses: &Addresses,
    query_type: RecordType,
) -> Message {
    let mut response = base_response(client);
    response.metadata.authoritative = true;
    let name = client.queries[0].name.clone();

    match query_type {
        RecordType::A => {
            for address in &addresses.v4 {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    HOSTS_TTL,
                    RData::A(A(*address)),
                ));
            }
        }
        RecordType::AAAA => {
            for address in &addresses.v6 {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    HOSTS_TTL,
                    RData::AAAA(AAAA(*address)),
                ));
            }
        }
        RecordType::ANY => {
            for address in &addresses.v4 {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    HOSTS_TTL,
                    RData::A(A(*address)),
                ));
            }
            for address in &addresses.v6 {
                response.add_answer(Record::from_rdata(
                    name.clone(),
                    HOSTS_TTL,
                    RData::AAAA(AAAA(*address)),
                ));
            }
        }
        _ => {}
    }

    if response.answers.is_empty() {
        add_negative_soa(&mut response, HOSTS_TTL);
    }
    response
}

fn ptr_response(client: &Message, hostname: &str) -> Message {
    let mut response = base_response(client);
    response.metadata.authoritative = true;
    let name = client.queries[0].name.clone();
    match Name::from_ascii(hostname) {
        Ok(target) => {
            response.add_answer(Record::from_rdata(name, HOSTS_TTL, RData::PTR(PTR(target))));
        }
        Err(_) => {
            response.metadata.response_code = ResponseCode::ServFail;
        }
    }
    response
}

fn deny_response(
    client: &Message,
    mode: DenyMode,
    query_type: RecordType,
    entry_address: Option<IpAddr>,
) -> Message {
    let mut response = base_response(client);
    response.metadata.authoritative = true;
    let name = client.queries[0].name.clone();

    if mode == DenyMode::Nx {
        response.metadata.response_code = ResponseCode::NXDomain;
        add_negative_soa(&mut response, DENY_TTL);
        return response;
    }

    let (v4, v6) = match mode {
        DenyMode::Zero => (
            Some(std::net::Ipv4Addr::UNSPECIFIED),
            Some(std::net::Ipv6Addr::UNSPECIFIED),
        ),
        DenyMode::Loopback => (
            Some(std::net::Ipv4Addr::LOCALHOST),
            Some(std::net::Ipv6Addr::LOCALHOST),
        ),
        DenyMode::Ip { ipv4, ipv6 } => (ipv4, ipv6),
        DenyMode::IpEntry => match entry_address {
            Some(IpAddr::V4(address)) if !address.is_unspecified() => (Some(address), None),
            Some(IpAddr::V6(address)) if !address.is_unspecified() => (None, Some(address)),
            _ => (
                Some(std::net::Ipv4Addr::UNSPECIFIED),
                Some(std::net::Ipv6Addr::UNSPECIFIED),
            ),
        },
        DenyMode::Nx => unreachable!(),
    };

    if matches!(query_type, RecordType::A | RecordType::ANY) {
        if let Some(address) = v4 {
            response.add_answer(Record::from_rdata(
                name.clone(),
                DENY_TTL,
                RData::A(A(address)),
            ));
        }
    }
    if matches!(query_type, RecordType::AAAA | RecordType::ANY) {
        if let Some(address) = v6 {
            response.add_answer(Record::from_rdata(
                name,
                DENY_TTL,
                RData::AAAA(AAAA(address)),
            ));
        }
    }

    if response.answers.is_empty() {
        add_negative_soa(&mut response, DENY_TTL);
    }
    response
}

/// Detect answers that resolve only to `0.0.0.0` / `::` and replace them with
/// the configured deny response.  Mixed or concrete answers pass through.
/// Returns true when the response was transformed.
fn apply_null_answer_policy(client: &Message, response: &mut Message, mode: DenyMode) -> bool {
    let query_type = client.queries[0].query_type;
    if !is_null_answer(response, query_type) {
        return false;
    }

    *response = deny_response(client, mode, query_type, None);
    // The synthesized answer is not covered by the upstream's signatures.
    response.metadata.authentic_data = false;
    true
}

fn is_null_answer(response: &Message, query_type: RecordType) -> bool {
    let mut saw_address = false;
    for record in &response.answers {
        let unspecified = match (&record.data, query_type) {
            (RData::A(address), RecordType::A | RecordType::ANY) => address.0.is_unspecified(),
            (RData::AAAA(address), RecordType::AAAA | RecordType::ANY) => {
                address.0.is_unspecified()
            }
            _ => continue,
        };
        if !unspecified {
            return false;
        }
        saw_address = true;
    }
    saw_address
}

fn add_negative_soa(response: &mut Message, ttl: u32) {
    let soa = SOA::new(Name::root(), Name::root(), 0, 0, 0, 0, ttl);
    response.add_authority(Record::from_rdata(Name::root(), ttl, RData::SOA(soa)));
}

fn decrement_ttls(message: &mut Message, age: u32) {
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        if record.record_type() != RecordType::OPT {
            record.ttl = record.ttl.saturating_sub(age);
        }
    }
}

async fn shutdown_requested(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message, OpCode, Query, ResponseCode},
        rr::{
            rdata::{A, AAAA, CNAME},
            Name, RData, Record, RecordType,
        },
    };

    use super::*;
    use crate::cache::{CacheKey, DnsCache};

    fn query(name: &str, query_type: RecordType) -> Message {
        let mut message = Message::query();
        message.add_query(Query::query(Name::from_ascii(name).unwrap(), query_type));
        message
    }

    fn response(client: &Message, records: Vec<RData>) -> Message {
        let mut response = Message::response(client.metadata.id, OpCode::Query);
        response.metadata.recursion_available = true;
        response.queries = client.queries.clone();
        let name = client.queries[0].name.clone();
        for rdata in records {
            response.add_answer(Record::from_rdata(name.clone(), 300, rdata));
        }
        response
    }

    fn null_a() -> RData {
        RData::A(A::new(0, 0, 0, 0))
    }

    fn null_aaaa() -> RData {
        RData::AAAA(AAAA::new(0, 0, 0, 0, 0, 0, 0, 0))
    }

    fn concrete_a() -> RData {
        RData::A(A::new(192, 0, 2, 1))
    }

    fn has_soa(response: &Message) -> bool {
        response
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::SOA)
    }

    #[test]
    fn rewrites_null_a_answers() {
        let client = query("ads.example.", RecordType::A);

        let mut message = response(&client, vec![null_a()]);
        assert!(apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Nx
        ));
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        assert!(message.answers.is_empty());
        assert!(has_soa(&message));

        let mut message = response(&client, vec![null_a()]);
        assert!(apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Zero
        ));
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(
            matches!(&message.answers[0].data, RData::A(address) if address.0.is_unspecified())
        );

        let mut message = response(&client, vec![null_a()]);
        assert!(apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Loopback
        ));
        assert!(matches!(&message.answers[0].data, RData::A(address) if address.0.is_loopback()));

        let mode = DenyMode::Ip {
            ipv4: Some("10.0.0.1".parse().unwrap()),
            ipv6: None,
        };
        let mut message = response(&client, vec![null_a()]);
        assert!(apply_null_answer_policy(&client, &mut message, mode));
        assert!(
            matches!(&message.answers[0].data, RData::A(address) if address.0.to_string() == "10.0.0.1")
        );
    }

    #[test]
    fn rewrites_null_aaaa_answers() {
        let client = query("ads.example.", RecordType::AAAA);

        let mut message = response(&client, vec![null_aaaa()]);
        assert!(apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Loopback
        ));
        assert!(
            matches!(&message.answers[0].data, RData::AAAA(address) if address.0.is_loopback())
        );
    }

    #[test]
    fn missing_ip_family_yields_nodata() {
        let client = query("ads.example.", RecordType::AAAA);
        let mode = DenyMode::Ip {
            ipv4: Some("10.0.0.1".parse().unwrap()),
            ipv6: None,
        };

        let mut message = response(&client, vec![null_aaaa()]);
        assert!(apply_null_answer_policy(&client, &mut message, mode));
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.is_empty());
        assert!(has_soa(&message));
    }

    #[test]
    fn concrete_and_mixed_answers_pass_through() {
        let client = query("example.com.", RecordType::A);

        let mut message = response(&client, vec![concrete_a()]);
        assert!(!apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Nx
        ));
        assert_eq!(message.answers.len(), 1);

        let mut message = response(&client, vec![null_a(), concrete_a()]);
        assert!(!apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Nx
        ));
        assert_eq!(message.answers.len(), 2);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    }

    #[test]
    fn follows_a_cname_to_a_null_address() {
        let client = query("ads.example.", RecordType::A);
        let cname = RData::CNAME(CNAME(Name::from_ascii("blocked.example.").unwrap()));

        let mut message = response(&client, vec![cname, null_a()]);
        assert!(apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Nx
        ));
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        assert!(message.answers.is_empty());
        assert!(has_soa(&message));
    }

    #[test]
    fn existing_nxdomain_is_not_rewritten_again() {
        let client = query("missing.example.", RecordType::A);
        let mut message = response(&client, vec![]);
        message.metadata.response_code = ResponseCode::NXDomain;
        add_negative_soa(&mut message, 60);
        let authorities = message.authorities.len();

        assert!(!apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Nx
        ));
        assert_eq!(message.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(message.authorities.len(), authorities);
    }

    #[test]
    fn legacy_ip_mode_still_uses_the_deny_entry_address() {
        let client = query("ads.example.", RecordType::A);
        let address = Some("10.9.8.7".parse().unwrap());
        let message = deny_response(&client, DenyMode::IpEntry, RecordType::A, address);
        assert!(matches!(&message.answers[0].data, RData::A(a) if a.0.to_string() == "10.9.8.7"));
    }

    #[test]
    fn direct_rewrite_includes_the_cname_chain() {
        let client = query("gamespy.com.", RecordType::A);
        let target = Name::from_ascii("openspy.net.").unwrap();
        let chain = vec![(client.queries[0].name.clone(), target.clone())];
        let direct = DirectRewrite::Records(vec![RData::A(A::new(1, 2, 3, 4))]);

        let message = direct_rewrite_response(&client, &chain, direct);
        assert!(message.metadata.authoritative);
        assert_eq!(message.answers.len(), 2);
        assert!(matches!(&message.answers[0].data, RData::CNAME(_)));
        assert_eq!(&message.answers[1].name, &target);
    }

    #[test]
    fn rewrite_without_a_matching_record_is_nodata() {
        let client = query("v4.test.", RecordType::AAAA);
        let message = direct_rewrite_response(&client, &[], DirectRewrite::Records(Vec::new()));
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.is_empty());
        assert!(has_soa(&message));
    }

    #[tokio::test]
    async fn caches_the_rewritten_answer() {
        let client = query("ads.example.", RecordType::A);
        let mut message = response(&client, vec![null_a()]);
        assert!(apply_null_answer_policy(
            &client,
            &mut message,
            DenyMode::Nx
        ));

        let cache = DnsCache::new(86_400, 3_600);
        let key = CacheKey::from_query(&client, false).unwrap();
        assert_eq!(cache.insert(key.clone(), &mut message).await, Some(3_600));

        let entry = cache.get(&key).await.unwrap();
        assert!(entry.negative);
        assert_eq!(entry.message.metadata.response_code, ResponseCode::NXDomain);
        assert!(entry.message.answers.is_empty());
        assert!(has_soa(&entry.message));
    }

    #[test]
    fn reads_the_doh_dns_query_parameter() {
        let uri: hyper::Uri = "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
            .parse()
            .unwrap();
        let value = query_parameter(&uri, "dns").unwrap();
        let wire = decode_dns_parameter(&value).unwrap();
        assert_eq!(&wire, b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01");

        assert_eq!(percent_decode("AA%3D%3D"), "AA==");
        assert_eq!(
            decode_dns_parameter(&percent_decode("AA%3D%3D")).unwrap(),
            vec![0u8]
        );
    }

    #[test]
    fn rejects_invalid_doh_parameters() {
        let uri: hyper::Uri = "/dns-query?dns=***".parse().unwrap();
        assert!(decode_dns_parameter(&query_parameter(&uri, "dns").unwrap()).is_none());

        let uri: hyper::Uri = "/dns-query".parse().unwrap();
        assert!(query_parameter(&uri, "dns").is_none());
    }
}
