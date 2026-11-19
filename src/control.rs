//! Local Unix-socket control channel used by the cache purge CLI.
//!
//! The running server owns the in-memory cache, so a purge must reach the
//! process rather than only editing the snapshot files.  The socket accepts one
//! newline-terminated command and replies with one line:
//!
//! ```text
//! PURGE example.com   ->  OK 12
//! PURGE-ALL           ->  OK 340
//! ```

use std::{
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::watch,
    task::JoinHandle,
};
use tracing::{debug, info, warn};

use crate::{
    cache::{normalize_purge_domain, DnsCache},
    config::CacheConfig,
};

const MAX_COMMAND_BYTES: usize = 1024;

/// Bind the control socket, replacing a stale socket file at the same path.
pub fn bind(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove stale socket {}", path.display()))?;
        }
        Ok(_) => bail!(
            "control socket path {} exists and is not a socket",
            path.display()
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("failed to bind control socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to restrict permissions on {}", path.display()))?;
    Ok(listener)
}

/// Serve purge requests until shutdown, removing the socket file on exit.
pub fn serve(
    listener: UnixListener,
    path: PathBuf,
    cache: Arc<DnsCache>,
    config: CacheConfig,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!(path = %path.display(), "cache control socket listening");

        loop {
            tokio::select! {
                _ = shutdown_requested(&mut shutdown) => break,
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let cache = cache.clone();
                            let config = config.clone();
                            tokio::spawn(async move {
                                if let Err(error) = handle(stream, cache, config).await {
                                    debug!(%error, "cache control request failed");
                                }
                            });
                        }
                        Err(error) => warn!(%error, "cache control socket accept failed"),
                    }
                }
            }
        }

        drop(listener);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                debug!(path = %path.display(), %error, "failed to remove control socket");
            }
        }
    })
}

/// Send one command to a running server.
pub async fn request(path: &Path, command: &str) -> Result<String> {
    let mut stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("failed to connect to control socket {}", path.display()))?;
    stream
        .write_all(command.as_bytes())
        .await
        .context("failed to send control command")?;
    stream
        .write_all(b"\n")
        .await
        .context("failed to send control command")?;
    stream
        .flush()
        .await
        .context("failed to send control command")?;

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .await
        .context("failed to read control response")?;
    if response.is_empty() {
        bail!(
            "control socket {} closed without a response",
            path.display()
        );
    }
    Ok(response.trim_end().to_string())
}

/// True when the failure means no server is listening on the socket.
pub fn socket_unavailable(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| {
            matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::ConnectionRefused
            )
        })
}

async fn handle(stream: UnixStream, cache: Arc<DnsCache>, config: CacheConfig) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();
    BufReader::new(reader)
        .read_line(&mut line)
        .await
        .context("failed to read control command")?;
    if line.len() > MAX_COMMAND_BYTES {
        bail!("control command is too long");
    }

    let command = line.trim();
    let response = if command == "PURGE-ALL" {
        let removed = cache.purge_all().await;
        match cache.save_to_config(&config).await {
            Ok(()) => {
                info!(removed, "purged the whole cache");
                format!("OK {removed}")
            }
            Err(error) => format!("ERR failed to save cache snapshots: {error:#}"),
        }
    } else if let Some(raw_domain) = command.strip_prefix("PURGE ") {
        match normalize_purge_domain(raw_domain) {
            Ok(domain) => {
                let removed = cache.purge_domain(&domain).await;
                match cache.save_to_config(&config).await {
                    Ok(()) => {
                        info!(%domain, removed, "purged cached domain");
                        format!("OK {removed}")
                    }
                    Err(error) => format!("ERR failed to save cache snapshots: {error:#}"),
                }
            }
            Err(error) => format!("ERR {error}"),
        }
    } else {
        "ERR unknown command".to_string()
    };

    writer
        .write_all(response.as_bytes())
        .await
        .context("failed to send control response")?;
    writer
        .write_all(b"\n")
        .await
        .context("failed to send control response")?;
    writer.flush().await.context("failed to flush response")?;
    Ok(())
}

async fn shutdown_requested(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    let _ = receiver.changed().await;
}
