//! Test du chemin `PrivateKeyMaterial::Keystore` : la clé n'est jamais passée
//! à rustls directement, elle vit "ailleurs". Notre `KeystoreSigner` mock
//! détient une clé ECDSA P-256 chargée en RAM via rustls/aws-lc-rs et signe à
//! la demande. Côté Android la vraie implémentation passera par
//! `Signature.getInstance("SHA256withECDSA").initSign(privateKey)` où
//! `privateKey` est un handle Keystore non-exportable.

use std::sync::Arc;

use mtls_bridge_core::config::{
    ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust,
};
use mtls_bridge_core::error::Result;
use mtls_bridge_core::init_crypto_provider;
use mtls_bridge_core::proxy::{bridge_to_mtls_upstream, precompile_client_config};
use mtls_bridge_core::signer::{
    scheme_to_rustls, KeystoreSigner, SignerError, TlsSignatureScheme,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::crypto::aws_lc_rs;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// ---------- Mock KeystoreSigner ----------

#[derive(Debug)]
struct TestSigner {
    rustls_key: Arc<dyn rustls::sign::SigningKey>,
}

impl TestSigner {
    fn from_pkcs8_pem(pem: &[u8]) -> Self {
        let mut cur = Cursor::new(pem);
        let der = rustls_pemfile::pkcs8_private_keys(&mut cur)
            .next()
            .unwrap()
            .unwrap();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            der.secret_pkcs8_der().to_vec(),
        ));
        let rustls_key = aws_lc_rs::sign::any_supported_type(&key_der).unwrap();
        Self { rustls_key }
    }
}

impl KeystoreSigner for TestSigner {
    fn sign(
        &self,
        _key_handle: String,
        scheme: TlsSignatureScheme,
        data: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, SignerError> {
        let rustls_scheme = scheme_to_rustls(scheme);
        let signer = self
            .rustls_key
            .choose_scheme(&[rustls_scheme])
            .ok_or(SignerError::Unsupported)?;
        signer
            .sign(&data)
            .map_err(|e| SignerError::Failed(e.to_string()))
    }

    fn supported_schemes(&self, _key_handle: String) -> Vec<TlsSignatureScheme> {
        // Notre clé de test est ECDSA P-256 (rcgen default).
        vec![TlsSignatureScheme::EcdsaNistp256Sha256]
    }
}

// ---------- PKI helpers (alignées sur mtls_bridge.rs) ----------

struct Pki {
    ca_pem: Vec<u8>,
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_chain_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    let mut ca_params = CertificateParams::new(vec!["mtls_bridge-ks-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mtls_bridge ks test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut srv_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    srv_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let srv_key = KeyPair::generate().unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let mut cli_params = CertificateParams::new(vec!["ks-test-client".to_string()]).unwrap();
    cli_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cli_params
        .distinguished_name
        .push(DnType::CommonName, "ks-test-client");
    let cli_key = KeyPair::generate().unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

    Pki {
        ca_pem: ca_cert.pem().into_bytes(),
        server_chain_pem: srv_cert.pem().into_bytes(),
        server_key_pem: srv_key.serialize_pem().into_bytes(),
        client_chain_pem: cli_cert.pem().into_bytes(),
        client_key_pem: cli_key.serialize_pem().into_bytes(),
    }
}

fn parse_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    let mut cur = Cursor::new(pem);
    rustls_pemfile::certs(&mut cur)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
}

fn parse_pkcs8(pem: &[u8]) -> PrivateKeyDer<'static> {
    let mut cur = Cursor::new(pem);
    let der = rustls_pemfile::pkcs8_private_keys(&mut cur)
        .next()
        .unwrap()
        .unwrap();
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.secret_pkcs8_der().to_vec()))
}

async fn spawn_mtls_echo_server(pki: &Pki) -> u16 {
    let mut roots = RootCertStore::empty();
    for ca in parse_certs(&pki.ca_pem) {
        roots.add(ca).unwrap();
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(parse_certs(&pki.server_chain_pem), parse_pkcs8(&pki.server_key_pem))
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                let body = if std::str::from_utf8(&buf[..n])
                    .unwrap_or("")
                    .starts_with("GET /pong")
                {
                    "ks-ok"
                } else {
                    "?"
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    port
}

// ---------- Le test ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn callback_keystore_signer_completes_mtls_handshake() -> Result<()> {
    init_crypto_provider();

    let pki = build_pki();
    let port = spawn_mtls_echo_server(&pki).await;

    // Le signer "Keystore" simulé tient la clé client. La struct ProxyConfig
    // n'a *que* le handle + l'instance signer — pas la clé elle-même.
    let signer: Arc<dyn KeystoreSigner> =
        Arc::new(TestSigner::from_pkcs8_pem(&pki.client_key_pem));

    let cfg = ProxyConfig {
        id: "ks-test".into(),
        upstream_host: "localhost".into(),
        upstream_port: port,
        sni: Some("localhost".into()),
        identity: ClientIdentity {
            cert_chain_pem: Arc::new(pki.client_chain_pem.clone()),
            key: PrivateKeyMaterial::Keystore {
                handle: "ks-test-alias".into(),
                signer,
            },
        },
        server_trust: ServerTrust::Pinned(Arc::new(pki.ca_pem.clone())),
        path_token: None,
        extra_canonical_hosts: Vec::new(),
    };
    let client_config = precompile_client_config(&cfg)?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = listener.local_addr()?.port();
    let cfg_clone = cfg.clone();
    let cc_clone = client_config.clone();
    let proxy_task = tokio::spawn(async move {
        let (inbound, _) = listener.accept().await?;
        bridge_to_mtls_upstream(inbound, cc_clone, &cfg_clone, None).await
    });

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    client
        .write_all(b"GET /pong HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    client.shutdown().await?;
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut response),
    )
    .await
    .expect("timeout")?;
    proxy_task.await.unwrap()?;

    let body = String::from_utf8_lossy(&response);
    assert!(body.contains("HTTP/1.1 200 OK"), "réponse : {body}");
    assert!(body.ends_with("ks-ok"), "corps : {body}");
    Ok(())
}
