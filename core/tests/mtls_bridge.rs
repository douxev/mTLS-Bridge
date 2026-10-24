//! Test d'intégration end-to-end :
//!
//! 1. On génère une PKI complète en mémoire avec rcgen : CA, cert serveur
//!    (SAN=localhost), cert client.
//! 2. On lance un faux serveur HTTPS qui exige l'auth client (mTLS) sur un
//!    port aléatoire — quand il reçoit "GET /ping", il répond "pong".
//! 3. On précompile une `ProxyConfig` avec la clé/cert client en RAM.
//! 4. On ouvre une socket TCP vers le serveur via notre `bridge_to_mtls_upstream`
//!    et on écrit "GET /ping". On attend "pong" en retour.
//!
//! Si tout passe, on a prouvé que la chaîne complète (parsing PEM →
//! ClientConfig rustls → handshake mTLS → tunnel bidirectionnel) marche.

use std::sync::Arc;

use mtls_bridge_core::config::{
    ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust,
};
use mtls_bridge_core::proxy::{bridge_to_mtls_upstream, precompile_client_config};
use mtls_bridge_core::{error::Result, init_crypto_provider};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

struct Pki {
    ca_pem: Vec<u8>,
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_chain_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    // ---------- CA ----------
    let mut ca_params = CertificateParams::new(vec!["mtls_bridge-test-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mtls_bridge test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // ---------- Serveur (SAN = localhost) ----------
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

    // ---------- Client ----------
    let mut cli_params = CertificateParams::new(vec!["mtls_bridge-test-client".to_string()]).unwrap();
    cli_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cli_params
        .distinguished_name
        .push(DnType::CommonName, "test-client");
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
        .expect("au moins une clé pkcs8")
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
                let n = match tls.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                // Réponse HTTP minimaliste indépendante du chemin demandé.
                let req = std::str::from_utf8(&buf[..n]).unwrap_or("");
                let body = if req.starts_with("GET /ping") {
                    "pong"
                } else {
                    "unknown"
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_streams_plaintext_to_mtls_upstream() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    init_crypto_provider();

    let pki = build_pki();
    let port = spawn_mtls_echo_server(&pki).await;

    let cfg = ProxyConfig {
        id: "test".into(),
        upstream_host: "localhost".into(),
        upstream_port: port,
        sni: Some("localhost".into()),
        identity: ClientIdentity {
            cert_chain_pem: Arc::new(pki.client_chain_pem.clone()),
            key: PrivateKeyMaterial::InMemoryPem(Arc::new(pki.client_key_pem.clone())),
        },
        server_trust: ServerTrust::Pinned(Arc::new(pki.ca_pem.clone())),
        path_token: None,
        extra_canonical_hosts: Vec::new(),
    };
    let client_config = precompile_client_config(&cfg)?;

    // On simule l'app cliente : on connecte une vraie TcpStream "client" via une
    // paire socket → bridge_to_mtls_upstream prend l'autre bout.
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
        .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    // Half-close write côté client : sans ça, copy_bidirectional attend EOF
    // sur les deux sens et le test bloque indéfiniment.
    client.shutdown().await?;

    let mut response = Vec::new();
    // Timeout de sécurité : si le pont a un souci de propagation, on échoue
    // explicitement au lieu de pendre la CI.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_to_end(&mut response),
    )
    .await
    .expect("timeout en attente de la réponse upstream")?;
    proxy_task.await.unwrap()?;

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.contains("HTTP/1.1 200 OK"),
        "réponse inattendue : {response_str:?}"
    );
    assert!(
        response_str.ends_with("pong"),
        "corps inattendu : {response_str:?}"
    );
    Ok(())
}
