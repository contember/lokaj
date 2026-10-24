//! TLS configuration: client-facing, and towards the server.

use std::path::Path;
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("cannot load {path}: {source}")]
    Pem {
        path: String,
        source: rustls_pki_types::pem::Error,
    },
    #[error("{0} contains no certificate")]
    NoCertificate(String),
    #[error("{0} is not a valid server name")]
    ServerName(String),
    #[error("invalid TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let pem_error = |source| TlsError::Pem {
        path: path.display().to_string(),
        source,
    };
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(pem_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(pem_error)?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificate(path.display().to_string()));
    }
    Ok(certs)
}

pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    let certs = certificates(cert)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|source| TlsError::Pem {
        path: key.display().to_string(),
        source,
    })?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

/// Server connections trust only the certificates in `ca`.
pub fn client_config(ca: &Path) -> Result<Arc<ClientConfig>, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(ca)? {
        roots.add(cert)?;
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The name server certificates must match: a DNS name, or an IP address literal.
pub fn server_name(host: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(host.to_owned()).map_err(|_| TlsError::ServerName(host.to_owned()))
}
