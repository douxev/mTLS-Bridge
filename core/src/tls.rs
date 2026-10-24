use std::io::Cursor;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, SignatureAlgorithm};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::{PrivateKeyMaterial, ProxyConfig, ServerTrust};
use crate::error::{CoreError, Result};
use crate::signer::{
    scheme_to_rustls, CallbackResolvesClientCert, CallbackSigningKey, TlsSignatureScheme,
};

/// Construit le `ClientConfig` rustls pour une config donnée.
///
/// Pour l'instant on supporte uniquement [`PrivateKeyMaterial::InMemoryPem`].
/// Le branchement Keystore (signing callback) arrive en phase C — il passera
/// par `ClientConfig::with_client_cert_resolver`.
pub fn build_client_config(cfg: &ProxyConfig) -> Result<Arc<ClientConfig>> {
    let root_store = build_root_store(&cfg.server_trust)?;

    // On force le verifier WebPKI sur ce root store : pas de hostname-validation
    // skip, pas d'ALPN custom. SNI = cfg.sni ou upstream_host (géré au connect).
    let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| CoreError::Tls(format!("verifier build: {e}")))?;

    let builder = ClientConfig::builder()
        .dangerous() // nécessaire pour with_custom_certificate_verifier ; on lui
        // passe WebPkiServerVerifier qui est strict, donc pas réellement dangereux.
        .with_custom_certificate_verifier(verifier);

    let config = match &cfg.identity.key {
        PrivateKeyMaterial::InMemoryPem(key_pem) => {
            let chain = parse_cert_chain(&cfg.identity.cert_chain_pem)?;
            let key = parse_private_key(key_pem)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| CoreError::Tls(format!("with_client_auth_cert: {e}")))?
        }
        PrivateKeyMaterial::Keystore { handle, signer } => {
            let chain = parse_cert_chain(&cfg.identity.cert_chain_pem)?;
            let supported_our =
                crate::runtime::blocking(|| signer.supported_schemes(handle.clone()));
            if supported_our.is_empty() {
                return Err(CoreError::Config(
                    "le KeystoreSigner ne déclare aucun schéma supporté".into(),
                ));
            }
            let supported: Vec<_> = supported_our
                .iter()
                .copied()
                .map(scheme_to_rustls)
                .collect();
            let algorithm = infer_algorithm(&supported_our);
            let signing_key = Arc::new(CallbackSigningKey {
                handle: handle.clone(),
                callback: Arc::clone(signer),
                supported,
                algorithm,
            });
            let certified = Arc::new(CertifiedKey {
                cert: chain,
                key: signing_key,
                ocsp: None,
            });
            let resolver = Arc::new(CallbackResolvesClientCert { certified });
            builder.with_client_cert_resolver(resolver)
        }
    };

    Ok(Arc::new(config))
}

fn infer_algorithm(schemes: &[TlsSignatureScheme]) -> SignatureAlgorithm {
    use TlsSignatureScheme::*;
    // Les schémas exposés par une même clé sont homogènes (EC ou RSA), donc
    // on regarde juste le premier.
    match schemes.first() {
        Some(EcdsaNistp256Sha256) | Some(EcdsaNistp384Sha384) => SignatureAlgorithm::ECDSA,
        _ => SignatureAlgorithm::RSA,
    }
}

fn build_root_store(trust: &ServerTrust) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    match trust {
        ServerTrust::Pinned(pem) => {
            let certs = parse_cert_chain(pem)?;
            for c in certs {
                store
                    .add(c)
                    .map_err(|e| CoreError::Tls(format!("add root: {e}")))?;
            }
        }
        ServerTrust::SystemRoots => {
            return Err(CoreError::Config(
                "SystemRoots non implémenté ; épingle une CA explicitement".into(),
            ));
        }
    }
    Ok(store)
}

fn parse_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = Cursor::new(pem);
    rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| CoreError::Pem(format!("certs: {e}")))
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = Cursor::new(pem);
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|e| CoreError::Pem(format!("private_key: {e}")))?
        .ok_or_else(|| CoreError::Pem("aucune clé privée trouvée".into()))
}
