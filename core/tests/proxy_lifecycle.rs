//! Cycle de vie du proxy, de bout en bout contre un vrai serveur mTLS :
//! - les URLs réécrites en mode loopback portent le token de path et sont
//!   acceptées quand le client les suit,
//! - `LoopbackHandle::stop()` ferme aussi les sessions keepalive en cours,
//! - un upstream IPv6 littéral (`::1`) est joignable,
//! - `start_vpn` ferme le tun_fd quand la table de routage est invalide.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mtls_bridge_core::config::{
    ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust,
};
use mtls_bridge_core::error::Result;
use mtls_bridge_core::init_crypto_provider;
use mtls_bridge_core::loopback::{
    start_loopback, AuditLogger, PeerUidResolver, ProxyEvent,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// --- PKI helpers (dupliqués volontairement : chaque fichier de test reste
// autonome). ---

struct Pki {
    ca_pem: Vec<u8>,
    server_chain_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_chain_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn build_pki() -> Pki {
    let mut ca = CertificateParams::new(vec!["mtls_bridge-life-ca".to_string()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name
        .push(DnType::CommonName, "mtls_bridge lifecycle CA");
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

    let mut cli = CertificateParams::new(vec!["life-client".to_string()]).unwrap();
    cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cli.distinguished_name.push(DnType::CommonName, "life-client");
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

/// Lit une réponse HTTP/1.1 complète (headers + body Content-Length).
/// `None` sur EOF avant la moindre donnée.
async fn read_response<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<(String, Vec<u8>)> {
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        let n = s.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = s.read(&mut tmp).await.unwrap();
        assert!(n > 0, "EOF au milieu du body");
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[head_end..head_end + len].to_vec();
    buf.drain(..head_end + len);
    Some((head, body))
}

/// Serveur HTTPS mTLS keepalive : ne ferme jamais la connexion de lui-même.
/// - `/json` → JSON contenant son URL canonique absolue,
/// - `/start` → 302 vers son URL canonique,
/// - `/next…` → `next-ok`,
/// - `/host` → la valeur du header `Host` reçu.
async fn spawn_keepalive_server(pki: &Pki, bind: &str) -> std::io::Result<u16> {
    let mut roots = RootCertStore::empty();
    for ca in parse_certs(&pki.ca_pem) {
        roots.add(ca).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
    let server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(parse_certs(&pki.server_chain_pem), parse_pkcs8(&pki.server_key_pem))
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind(bind).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(s).await else { return };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    let end = loop {
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        match tls.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    };
                    let req = String::from_utf8_lossy(&buf[..end]).to_string();
                    buf.drain(..end);
                    let path = req.split(' ').nth(1).unwrap_or("").to_string();
                    let canonical = format!("https://localhost:{port}");
                    let resp = if path == "/json" {
                        let body = format!(r#"{{"url":"{canonical}/next?x=1"}}"#);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                    } else if path == "/start" {
                        format!("HTTP/1.1 302 Found\r\nLocation: {canonical}/next\r\nContent-Length: 0\r\n\r\n")
                    } else if path == "/host" {
                        let host = req
                            .lines()
                            .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("host")))
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default();
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{host}", host.len())
                    } else if path.starts_with("/next") {
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\n\r\nnext-ok".to_string()
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                    };
                    if tls.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok(port)
}

// --- Test mocks ---

struct NoUid;
impl PeerUidResolver for NoUid {
    fn peer_uid(&self, _: String, _: u16, _: String, _: u16) -> Option<u32> {
        None
    }
}

#[derive(Default, Clone)]
struct CollectingAudit(Arc<Mutex<Vec<ProxyEvent>>>);
impl AuditLogger for CollectingAudit {
    fn record(&self, event: ProxyEvent) {
        self.0.lock().unwrap().push(event);
    }
}

fn make_cfg(pki: &Pki, host: &str, port: u16, token: Option<&str>) -> Arc<ProxyConfig> {
    Arc::new(ProxyConfig {
        id: "life".into(),
        upstream_host: host.into(),
        upstream_port: port,
        sni: Some("localhost".into()),
        identity: ClientIdentity {
            cert_chain_pem: Arc::new(pki.client_chain_pem.clone()),
            key: PrivateKeyMaterial::InMemoryPem(Arc::new(pki.client_key_pem.clone())),
        },
        server_trust: ServerTrust::Pinned(Arc::new(pki.ca_pem.clone())),
        path_token: token.map(str::to_string),
        extra_canonical_hosts: Vec::new(),
    })
}

async fn get(s: &mut TcpStream, buf: &mut Vec<u8>, path: &str) -> (String, Vec<u8>) {
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), read_response(s, buf))
        .await
        .expect("timeout en attente de la réponse")
        .expect("connexion fermée au lieu d'une réponse")
}

// --- Tests ---

/// Les URLs réécrites portent `/<token>` et passent le contrôle du token
/// quand le client les suit sur la même connexion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewritten_urls_carry_path_token_and_are_accepted() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let upstream = spawn_keepalive_server(&pki, "127.0.0.1:0").await?;
    let cfg = make_cfg(&pki, "localhost", upstream, Some("TOK123"));
    let audit = Arc::new(CollectingAudit::default());
    let h = start_loopback(cfg, 0, 1234, Arc::new(NoUid), audit as Arc<dyn AuditLogger>).await?;
    let base = format!("http://127.0.0.1:{}/TOK123", h.port());

    let mut s = TcpStream::connect(("127.0.0.1", h.port())).await?;
    let mut buf = Vec::new();

    let (_, body) = get(&mut s, &mut buf, "/TOK123/json").await;
    let body = String::from_utf8(body).unwrap();
    let next = format!("{base}/next?x=1");
    assert!(body.contains(&next), "body: {body}");

    let (head, _) = get(&mut s, &mut buf, "/TOK123/start").await;
    assert!(head.contains(&format!("Location: {base}/next\r\n")), "head: {head}");

    // Le client suit l'URL réécrite : le token est accepté et retiré.
    let path = next.strip_prefix(&format!("http://127.0.0.1:{}", h.port())).unwrap();
    let (head, body) = get(&mut s, &mut buf, path).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    assert_eq!(body, b"next-ok");
    h.stop();
    Ok(())
}

/// `stop()` ferme aussi les sessions en cours, même quand l'upstream garde
/// la connexion ouverte (keepalive).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stop_closes_active_sessions() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let upstream = spawn_keepalive_server(&pki, "127.0.0.1:0").await?;
    let cfg = make_cfg(&pki, "localhost", upstream, None);
    let audit = Arc::new(CollectingAudit::default());
    let h = start_loopback(
        cfg,
        0,
        1234,
        Arc::new(NoUid),
        audit.clone() as Arc<dyn AuditLogger>,
    )
    .await?;

    let mut s = TcpStream::connect(("127.0.0.1", h.port())).await?;
    let mut buf = Vec::new();
    let (_, body) = get(&mut s, &mut buf, "/next").await;
    assert_eq!(body, b"next-ok");

    h.stop();
    let mut tmp = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut tmp))
        .await
        .expect("la session doit être fermée par stop()")
        .unwrap_or(0);
    assert_eq!(n, 0, "EOF attendu après stop()");

    // L'événement Stopped arrive une fois les sessions fermées.
    tokio::time::timeout(Duration::from_secs(3), async {
        while !audit.0.lock().unwrap().iter().any(|e| matches!(e, ProxyEvent::Stopped)) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("événement Stopped");
    Ok(())
}

/// Upstream IPv6 littéral : connexion par tuple (host, port) et header
/// `Host` entre crochets (`Host: ::1` est invalide).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridge_connects_to_ipv6_literal_upstream() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let upstream = match spawn_keepalive_server(&pki, "[::1]:0").await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("IPv6 loopback indisponible ({e}), test ignoré");
            return Ok(());
        }
    };
    let cfg = make_cfg(&pki, "::1", upstream, None);
    let audit = Arc::new(CollectingAudit::default());
    let h = start_loopback(
        cfg,
        0,
        1234,
        Arc::new(NoUid),
        audit.clone() as Arc<dyn AuditLogger>,
    )
    .await?;
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).await?;
    let mut buf = Vec::new();
    let (head, body) = get(&mut s, &mut buf, "/next").await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    assert_eq!(body, b"next-ok");
    let (_, body) = get(&mut s, &mut buf, "/host").await;
    assert_eq!(body, b"[::1]", "Host reçu par l'upstream");
    h.stop();
    let events = audit.0.lock().unwrap().clone();
    assert!(
        !events.iter().any(|e| matches!(e, ProxyEvent::BridgeFailed { .. })),
        "events: {events:?}"
    );
    Ok(())
}

/// Route invalide (PEM vides) : `start_vpn` échoue mais ferme le tun_fd
/// qu'on lui a confié — sinon l'interface VPN resterait montée.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn start_vpn_closes_tun_fd_when_setup_fails() {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    use mtls_bridge_core::vpn::{start_vpn, VpnRoute};

    init_crypto_provider();
    let (ours, mut theirs) = UnixStream::pair().unwrap();
    theirs.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let route = VpnRoute {
        synthetic_ip: "192.0.2.1".parse().unwrap(),
        synthetic_port: 5001,
        config: Arc::new(ProxyConfig {
            id: "bad".into(),
            upstream_host: "x".into(),
            upstream_port: 1,
            sni: None,
            identity: ClientIdentity {
                cert_chain_pem: Arc::new(Vec::new()),
                key: PrivateKeyMaterial::InMemoryPem(Arc::new(Vec::new())),
            },
            server_trust: ServerTrust::Pinned(Arc::new(Vec::new())),
            path_token: None,
            extra_canonical_hosts: Vec::new(),
        }),
        expected_uid: 1,
    };
    let res = start_vpn(
        ours.into_raw_fd(),
        1500,
        vec![route],
        Arc::new(NoUid),
        Arc::new(CollectingAudit::default()),
    )
    .await;
    assert!(res.is_err(), "la route invalide doit faire échouer start_vpn");

    let mut b = [0u8; 1];
    let n = theirs
        .read(&mut b)
        .expect("le tun_fd doit être fermé (EOF), pas laissé ouvert");
    assert_eq!(n, 0);
}
