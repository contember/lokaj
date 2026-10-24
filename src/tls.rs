//! Client-facing TLS configuration.

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("cannot load {path}: {source}")]
    Pem {
        path: String,
        source: rustls_pki_types::pem::Error,
    },
    #[error("{0} contains no certificate")]
    NoCertificate(String),
    #[error("invalid TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
}

pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, TlsError> {
    let pem_error = |path: &Path| {
        let path = path.display().to_string();
        move |source| TlsError::Pem { path, source }
    };
    let certs = CertificateDer::pem_file_iter(cert)
        .map_err(pem_error(cert))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(pem_error(cert))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificate(cert.display().to_string()));
    }
    let key = PrivateKeyDer::from_pem_file(key).map_err(pem_error(key))?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}
