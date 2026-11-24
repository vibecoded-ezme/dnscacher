mod cache;
mod config;
mod control;
mod hosts;
mod rules;
mod server;
mod tls;
mod upstream;

use std::{
    io::IsTerminal,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{interval, MissedTickBehavior},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use cache::DnsCache;
use config::{CacheConfig, Config};
use hosts::HostsStore;
use rules::RulesStore;
use server::AppState;
use upstream::Resolver;

const TEMPORARY_FLUSH_INTERVAL: Duration = Duration::from_secs(15);
const PERSISTENT_FLUSH_INTERVAL: Duration = Duration::from_secs(300);
const HOSTS_RELOAD_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Parser)]
#[command(
    name = "dnscacher",
    version,
    about = "A caching DNS forwarder with UDP, TCP, DoT and DoH server and upstreams"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        env = "DNSCACHER_CONFIG",
        default_value = "/etc/dnscacher.toml"
    )]
    config: PathBuf,

    /// Override the listening port from the configuration file.
    #[arg(long)]
    port: Option<u16>,

    /// Override every listening address (may be repeated).
    #[arg(long = "address", value_name = "IP")]
    address: Vec<IpAddr>,

    /// Validate the configuration and print the effective settings.
    #[arg(long)]
    check: bool,

    /// Remove cached entries for a domain and its subdomains.
    #[arg(
        long,
        value_name = "DOMAIN",
        conflicts_with_all = ["purge_cache_all", "check"]
    )]
    purge_cache: Option<String>,

    /// Remove every cached entry.
    #[arg(long, conflicts_with_all = ["purge_cache", "check"])]
    purge_cache_all: bool,

    /// Log filter, for example "info" or "dnscacher=debug".
    #[arg(long, env = "DNSCACHER_LOG", default_value = "dnscacher=info,warn")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cli.log_level))
        .context("invalid log filter")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .with_target(false)
        .init();

    let mut config = Config::load(&cli.config)?;
    if let Some(port) = cli.port {
        config.server.port = port;
    }
    if !cli.address.is_empty() {
        config.server.address = cli.address.clone();
    }
    config.validate()?;

    if cli.check {
        print!("{}", config.summary());
        return Ok(());
    }

    if cli.purge_cache_all || cli.purge_cache.is_some() {
        let domain = match cli.purge_cache.as_deref() {
            Some(value) => Some(cache::normalize_purge_domain(value)?),
            None => None,
        };
        return purge_cache(&config, domain.as_deref()).await;
    }

    info!(
        config = %cli.config.display(),
        addresses = ?config.server.address,
        port = config.server.port,
        priority = ?config.dns.priority,
        dnssec = ?config.dns.dnssec,
        "starting dnscacher"
    );

    let cache = Arc::new(DnsCache::new(config.cache.ttl, config.cache.nx));
    cache.load_from_config(&config.cache).await?;

    let resolver = Resolver::new(&config)?;
    let hosts = HostsStore::new(config.dns.hosts.clone());
    let rules = RulesStore::new(config.dns.rules.clone());

    let state = Arc::new(AppState {
        cache: cache.clone(),
        resolver,
        hosts: hosts.clone(),
        rules: rules.clone(),
        dnssec: config.dns.dnssec,
        deny: config.dns.deny,
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let control_task = match &config.server.control {
        Some(path) => {
            let listener = control::bind(path)?;
            Some(control::serve(
                listener,
                path.clone(),
                cache.clone(),
                config.cache.clone(),
                shutdown_rx.clone(),
            ))
        }
        None => None,
    };

    let server_tasks = server::start(state.clone(), &config.server, shutdown_rx.clone()).await?;

    let mut flush_task =
        spawn_cache_flusher(cache.clone(), config.cache.clone(), shutdown_rx.clone());
    let reload_task = spawn_file_reloader(hosts.clone(), rules.clone(), shutdown_rx.clone());

    info!("dnscacher is ready");

    shutdown_signal().await;
    info!("shutdown requested");

    let _ = shutdown_tx.send(true);

    if let Some(mut task) = control_task {
        if tokio::time::timeout(Duration::from_secs(2), &mut task)
            .await
            .is_err()
        {
            warn!("control socket task did not stop in time; aborting it");
            task.abort();
        }
    }

    // Let the periodic flusher finish any in-progress write, then stop the
    // network tasks.
    if tokio::time::timeout(Duration::from_secs(5), &mut flush_task)
        .await
        .is_err()
    {
        warn!("cache flusher did not stop in time; aborting it");
        flush_task.abort();
    }
    for task in server_tasks {
        task.abort();
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), reload_task).await;

    if let Some(path) = &config.cache.persistent {
        if let Err(error) = cache.save_to(path).await {
            warn!(path = %path.display(), %error, "failed to save persistent cache");
        }
    }

    match (&config.cache.persistent, &config.cache.temporary) {
        // With a persistent cache, the temporary snapshot only exists to
        // recover from an unclean exit.
        (Some(persistent), Some(temporary)) if persistent != temporary => {
            match std::fs::remove_file(temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    warn!(path = %temporary.display(), %error, "failed to remove temporary cache");
                }
            }
        }
        // Temporary-only setups keep their snapshot across clean restarts.
        (None, Some(temporary)) => {
            if let Err(error) = cache.save_to(temporary).await {
                warn!(path = %temporary.display(), %error, "failed to save temporary cache");
            }
        }
        _ => {}
    }

    info!("dnscacher stopped");
    Ok(())
}

async fn purge_cache(config: &Config, domain: Option<&str>) -> Result<()> {
    let command = match domain {
        Some(domain) => format!("PURGE {domain}"),
        None => "PURGE-ALL".to_string(),
    };

    let mut tried_socket = false;
    if let Some(path) = &config.server.control {
        tried_socket = true;
        match control::request(path, &command).await {
            Ok(response) => {
                if let Some(count) = response.strip_prefix("OK ") {
                    match count.trim().parse::<usize>() {
                        Ok(removed) => {
                            print_purge_result(domain, removed);
                            return Ok(());
                        }
                        Err(_) => bail!("malformed response from control socket: {response:?}"),
                    }
                }
                bail!("cache purge failed: {response}");
            }
            Err(error) if control::socket_unavailable(&error) => {}
            Err(error) => return Err(error),
        }
    }

    let paths = config.cache.snapshot_paths();
    if paths.is_empty() {
        bail!("no [cache] persistent or temporary snapshot is configured");
    }

    let mut total = 0usize;
    for path in &paths {
        total += cache::purge_snapshot_file(path, domain)
            .with_context(|| format!("failed to purge {}", path.display()))?;
    }
    print_purge_result(domain, total);

    if tried_socket {
        println!("note: dnscacher was not running; only the snapshot files were changed");
    } else {
        println!(
            "note: no [server] control socket is configured; a running dnscacher keeps its in-memory entries"
        );
    }
    Ok(())
}

fn print_purge_result(domain: Option<&str>, removed: usize) {
    match domain {
        Some(domain) => {
            println!("purged {removed} cached entries for {domain} (including subdomains)")
        }
        None => println!("purged {removed} cached entries"),
    }
}

fn spawn_cache_flusher(
    cache: Arc<DnsCache>,
    config: CacheConfig,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(TEMPORARY_FLUSH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut last_persistent = Instant::now();

        loop {
            tokio::select! {
                _ = shutdown_requested(&mut shutdown) => break,
                _ = ticker.tick() => {}
            }

            if let Some(path) = &config.temporary {
                if let Err(error) = cache.save_to(path).await {
                    warn!(path = %path.display(), %error, "failed to save temporary cache");
                }
            }

            if last_persistent.elapsed() >= PERSISTENT_FLUSH_INTERVAL {
                if let Some(path) = &config.persistent {
                    if let Err(error) = cache.save_to(path).await {
                        warn!(path = %path.display(), %error, "failed to save persistent cache");
                    }
                }
                last_persistent = Instant::now();
            }
        }
    })
}

fn spawn_file_reloader(
    hosts: HostsStore,
    rules: RulesStore,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(HOSTS_RELOAD_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Consume the immediate first tick; the initial load already happened.
        ticker.tick().await;

        loop {
            tokio::select! {
                _ = shutdown_requested(&mut shutdown) => break,
                _ = ticker.tick() => {}
            }

            let hosts = hosts.clone();
            let rules = rules.clone();
            if let Err(error) = tokio::task::spawn_blocking(move || {
                hosts.reload();
                rules.reload();
            })
            .await
            {
                warn!(%error, "hosts/rules reload task failed");
            }
        }
    })
}

async fn shutdown_requested(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut terminate =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
