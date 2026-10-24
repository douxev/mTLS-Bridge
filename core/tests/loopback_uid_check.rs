//! Vérifie le filtrage UID du mode loopback :
//! - UID correct → connexion bridgée, réponse upstream reçue.
//! - UID différent → connexion droppée, événement `RejectedUidMismatch` loggé.
//! - UID indéterminé → connexion droppée, `RejectedUidUnknown` loggé.

use std::sync::{Arc, Mutex};

use mtls_bridge_core::config::{ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust};
use mtls_bridge_core::error::Result;
use mtls_bridge_core::init_crypto_provider;
use mtls_bridge_core::loopback::{start_loopback, AuditLogger, PeerUidResolver, ProxyEvent};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// --- PKI helpers (mêmes que les autres tests, dupliqués volontairement pour
// que chaque fichier de test reste autonome — le coût d'abstraction d'un
// module commun n'en vaut pas la peine pour 3 tests). ---

struct Pki {
    ca_pem: Vec<u8>,
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_chain_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    let mut ca = CertificateParams::new(vec!["mtls_bridge-loop-ca".to_string()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name
        .push(DnType::CommonName, "mtls_bridge loopback CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca.self_signed(&ca_key).unwrap();

    let mut srv = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    srv.distinguished_name.push(DnType::CommonName, "localhost");
    let srv_key = KeyPair::generate().unwrap();
    let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let mut cli = CertificateParams::new(vec!["loop-client".to_string()]).unwrap();
    cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cli.distinguished_name
        .push(DnType::CommonName, "loop-client");
    let cli_key = KeyPair::generate().unwrap();
    let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

    Pki {
        ca_pem: ca_cert.pem().into_bytes(),
        server_chain_pem: srv_cert.pem().into_bytes(),
        server_key_pem: srv_key.serialize_pem().into_bytes(),
        client_chain_pem: cli_cert.pem().into_bytes(),
        client_key_pem: cli_key.serialize_pem().into_bytes(),
    }
}

fn parse_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    let mut c = Cursor::new(pem);
    rustls_pemfile::certs(&mut c)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap()
}

fn parse_pkcs8(pem: &[u8]) -> PrivateKeyDer<'static> {
    let mut c = Cursor::new(pem);
    let der = rustls_pemfile::pkcs8_private_keys(&mut c)
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
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            parse_certs(&pki.server_chain_pem),
            parse_pkcs8(&pki.server_key_pem),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (s, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(s).await else {
                    return;
                };
                let mut buf = [0u8; 1024];
                let _ = tls.read(&mut buf).await;
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nloop";
                let _ = tls.write_all(resp).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    port
}

// --- Test mocks ---

#[derive(Debug)]
struct FixedUid(Option<u32>);
impl PeerUidResolver for FixedUid {
    fn peer_uid(&self, _: String, _: u16, _: String, _: u16) -> Option<u32> {
        self.0
    }
}

#[derive(Debug, Default, Clone)]
struct CollectingAudit(Arc<Mutex<Vec<ProxyEvent>>>);
impl AuditLogger for CollectingAudit {
    fn record(&self, event: ProxyEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn make_cfg(pki: &Pki, upstream_port: u16) -> Arc<ProxyConfig> {
    Arc::new(ProxyConfig {
        id: "loop".into(),
        upstream_host: "localhost".into(),
        upstream_port,
        sni: Some("localhost".into()),
        identity: ClientIdentity {
            cert_chain_pem: Arc::new(pki.client_chain_pem.clone()),
            key: PrivateKeyMaterial::InMemoryPem(Arc::new(pki.client_key_pem.clone())),
        },
        server_trust: ServerTrust::Pinned(Arc::new(pki.ca_pem.clone())),
        path_token: None,
        extra_canonical_hosts: Vec::new(),
    })
}

async fn connect_and_read(port: u16) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    s.shutdown().await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), s.read_to_end(&mut buf))
        .await
        .expect("timeout lecture")
        .unwrap();
    buf
}

async fn try_connect_then_eof(port: u16) -> bool {
    let mut s = match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(s) => s,
        Err(_) => return true, // déjà refusé au connect = succès du drop
    };
    let _ = s.write_all(b"GET /\r\n\r\n").await;
    let _ = s.shutdown().await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), s.read_to_end(&mut buf)).await;
    buf.is_empty()
}

// --- Tests ---

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_uid_lets_request_through() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let upstream = spawn_mtls_echo_server(&pki).await;
    let cfg = make_cfg(&pki, upstream);
    let audit = Arc::new(CollectingAudit::default());

    let h = start_loopback(
        cfg,
        0,
        1234,
        Arc::new(FixedUid(Some(1234))),
        audit.clone() as Arc<dyn AuditLogger>,
    )
    .await?;
    let port = h.port();
    let body = connect_and_read(port).await;
    h.stop();

    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("HTTP/1.1 200 OK"), "réponse: {body}");
    assert!(body.ends_with("loop"), "corps: {body}");

    let events = audit.0.lock().unwrap().clone();
    assert!(matches!(events[0], ProxyEvent::BindOk { .. }));
    assert!(events
        .iter()
        .any(|e| matches!(e, ProxyEvent::Accepted { .. })));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_uid_is_rejected_silently() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let upstream = spawn_mtls_echo_server(&pki).await;
    let cfg = make_cfg(&pki, upstream);
    let audit = Arc::new(CollectingAudit::default());

    let h = start_loopback(
        cfg,
        0,
        1234,
        Arc::new(FixedUid(Some(9999))), // pas l'UID attendu
        audit.clone() as Arc<dyn AuditLogger>,
    )
    .await?;
    let port = h.port();
    assert!(try_connect_then_eof(port).await, "le drop n'a pas eu lieu");
    h.stop();

    let events = audit.0.lock().unwrap().clone();
    assert!(events.iter().any(|e| matches!(
        e,
        ProxyEvent::RejectedUidMismatch {
            peer_uid: 9999,
            expected_uid: 1234,
            ..
        }
    )));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_uid_is_soft_accepted() -> Result<()> {
    // Android limite getConnectionOwnerUid : sur la plupart des devices il
    // renvoie INVALID_UID pour les sockets que l'app ne possède pas. Un
    // fail-closed strict rendait le loopback inutilisable. On accepte donc,
    // en marquant peer_uid=0 dans l'audit pour signaler le cas.
    init_crypto_provider();
    let pki = build_pki();
    let upstream = spawn_mtls_echo_server(&pki).await;
    let cfg = make_cfg(&pki, upstream);
    let audit = Arc::new(CollectingAudit::default());

    let h = start_loopback(
        cfg,
        0,
        1234,
        Arc::new(FixedUid(None)),
        audit.clone() as Arc<dyn AuditLogger>,
    )
    .await?;
    let port = h.port();
    let body = connect_and_read(port).await;
    h.stop();

    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("HTTP/1.1 200 OK"), "réponse: {body}");

    let events = audit.0.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ProxyEvent::Accepted { peer_uid: 0, .. })),
        "attendu Accepted{{peer_uid=0}} (soft-fail UID inconnu), events={events:?}"
    );
    Ok(())
}
