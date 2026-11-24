//! TLS material loading for the inbound DoT and DoH listeners.

use std::{path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use tokio_rustls::rustls::{
    pki_types::{
        pem::{PemObject, SectionKind},
        CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    },
    ServerConfig,
};

/// Load a PEM certificate chain and private key into a rustls server config.
///
/// `alpn` lists the protocols to advertise, in preference order.  DoT clients
/// do not send ALPN, so an empty list is fine for the DoT listener.
pub fn load_server_config(
    cert: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>> {
    let certificates = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("failed to read TLS certificate {}", cert.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse TLS certificate {}", cert.display()))?;
    if certificates.is_empty() {
        bail!(
            "TLS certificate {} contains no CERTIFICATE block",
            cert.display()
        );
    }

    let key = load_private_key(key_path)?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .with_context(|| {
            format!(
                "TLS certificate {} and key {} do not form a valid pair",
                cert.display(),
                key_path.display()
            )
        })?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let sections = <(SectionKind, Vec<u8>)>::pem_file_iter(path)
        .with_context(|| format!("failed to read TLS private key {}", path.display()))?;

    for section in sections {
        let (kind, der) = section
            .with_context(|| format!("failed to parse TLS private key {}", path.display()))?;
        let key = match kind {
            SectionKind::PrivateKey => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
            SectionKind::RsaPrivateKey => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
            SectionKind::EcPrivateKey => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
            _ => continue,
        };
        return Ok(key);
    }

    bail!(
        "TLS private key {} contains no PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY block",
        path.display()
    )
}
