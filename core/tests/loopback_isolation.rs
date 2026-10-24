//! Isolation du mode loopback, de bout en bout contre un vrai serveur mTLS :
//! - aucune connexion upstream (donc aucune signature avec la clé client)
//!   tant que la première requête n'a pas été lue et validée,
//! - le cookie de session posé par une URL avec token laisse passer les
//!   chemins absolus des webviews, ne part jamais vers l'upstream et ne
//!   survit pas à un redémarrage du proxy,
//! - une signature Keystore lente ne bloque pas les autres sessions,
//! - chaque refus du token est audité.

use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mtls_bridge_core::config::{
    ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust,
};
use mtls_bridge_core::error::Result;
use mtls_bridge_core::ffi_api::{start_loopback_proxy, ProxyConfigSpec};
use mtls_bridge_core::http_rewrite::TokenRejection;
use mtls_bridge_core::init_crypto_provider;
use mtls_bridge_core::loopback::{
    start_loopback, AuditLogger, PeerUidResolver, ProxyEvent,
};
use mtls_bridge_core::signer::{
    scheme_to_rustls, KeystoreSigner, SignerError, TlsSignatureScheme,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::crypto::aws_lc_rs;
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
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
    let mut ca = CertificateParams::new(vec!["mtls_bridge-iso-ca".to_string()]).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name
        .push(DnType::CommonName, "mtls_bridge isolation CA");
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

    let mut cli = CertificateParams::new(vec!["iso-client".to_string()]).unwrap();
    cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cli.distinguished_name.push(DnType::CommonName, "iso-client");
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

/// Serveur HTTPS mTLS keepalive qui compte les connexions TCP acceptées.
/// - `/next…` → `next-ok`,
/// - `/cookie` → la valeur du header `Cookie` reçu (vide si absent).
///
/// Sans reprise de session TLS : chaque connexion refait un handshake
/// complet, donc une signature avec la clé client.
async fn spawn_counting_server(pki: &Pki) -> (u16, Arc<AtomicUsize>) {
    let mut roots = RootCertStore::empty();
    for ca in parse_certs(&pki.ca_pem) {
        roots.add(ca).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().unwrap();
    let mut server_cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(parse_certs(&pki.server_chain_pem), parse_pkcs8(&pki.server_key_pem))
        .unwrap();
    server_cfg.session_storage = Arc::new(NoServerSessionStorage {});
    server_cfg.send_tls13_tickets = 0;
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
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
                    let resp = if path == "/cookie" {
                        let cookie = req
                            .lines()
                            .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("cookie")))
                            .map(|(_, v)| v.trim().to_string())
                            .unwrap_or_default();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{cookie}",
                            cookie.len()
                        )
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
    (port, accepted)
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

fn make_cfg(pki: &Pki, port: u16, token: Option<&str>) -> Arc<ProxyConfig> {
    Arc::new(ProxyConfig {
        id: "iso".into(),
        upstream_host: "localhost".into(),
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

async fn send_get(s: &mut TcpStream, path: &str, extra_headers: &str) {
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n{extra_headers}\r\n").as_bytes())
        .await
        .unwrap();
}

async fn get(s: &mut TcpStream, buf: &mut Vec<u8>, path: &str, extra_headers: &str) -> (String, Vec<u8>) {
    send_get(s, path, extra_headers).await;
    tokio::time::timeout(Duration::from_secs(5), read_response(s, buf))
        .await
        .expect("timeout en attente de la réponse")
        .expect("connexion fermée au lieu d'une réponse")
}

/// Le proxy ferme la connexion sans rien répondre.
async fn assert_closed_without_response(s: &mut TcpStream) {
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out))
        .await
        .expect("le proxy doit fermer la connexion")
        .ok();
    assert!(out.is_empty(), "aucune réponse attendue, reçu {:?}", String::from_utf8_lossy(&out));
}

/// Motifs des refus de token audités, une fois qu'il y en a `n` (l'événement
/// est enregistré à la fin de la session, juste après la fermeture vue par
/// le client).
async fn token_rejections(audit: &CollectingAudit, n: usize) -> Vec<TokenRejection> {
    let collect = || -> Vec<TokenRejection> {
        audit
            .0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                ProxyEvent::RejectedToken { config_id, reason } => {
                    assert_eq!(config_id, "iso");
                    Some(*reason)
                }
                _ => None,
            })
            .collect()
    };
    let wait = async {
        while collect().len() < n {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(5), wait).await;
    collect()
}

fn session_cookie(head: &str) -> String {
    let line = head
        .lines()
        .find(|l| l.starts_with("Set-Cookie: mtlsb_"))
        .unwrap_or_else(|| panic!("Set-Cookie de session absent: {head}"));
    let value = line.strip_prefix("Set-Cookie: ").unwrap();
    assert!(value.ends_with("; HttpOnly; SameSite=Strict; Path=/"), "{value}");
    value.split(';').next().unwrap().to_string()
}

// --- Tests ---

/// Connexions locales sans token valide : jamais de connexion upstream,
/// donc jamais de handshake mTLS ni de signature avec la clé client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_upstream_connection_before_first_request_is_validated() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let (upstream, accepted) = spawn_counting_server(&pki).await;
    let cfg = make_cfg(&pki, upstream, Some("TOK123"));
    let audit = Arc::new(CollectingAudit::default());
    let h = start_loopback(cfg, 0, 1234, Arc::new(NoUid), audit.clone() as Arc<dyn AuditLogger>).await?;
    let port = h.port();

    // Connexion ouverte puis fermée sans rien envoyer.
    drop(TcpStream::connect(("127.0.0.1", port)).await?);
    // Connexion ouverte qui n'envoie rien (scan de port) : reste ouverte.
    let idle = TcpStream::connect(("127.0.0.1", port)).await?;
    // Requête sans token ni cookie.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    send_get(&mut s, "/next", "").await;
    assert_closed_without_response(&mut s).await;
    // Mauvais token.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    send_get(&mut s, "/TOK12/next", "").await;
    assert_closed_without_response(&mut s).await;
    // Cookie forgé.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    send_get(&mut s, "/next", "Cookie: mtlsb_iso=00\r\n").await;
    assert_closed_without_response(&mut s).await;
    // Pas du HTTP (ClientHello TLS direct sur le port).
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    s.write_all(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\r\n\r\n").await?;
    assert_closed_without_response(&mut s).await;
    // Headers incomplets puis fermeture.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    s.write_all(b"GET /TOK123/next HTTP/1.1\r\nHo").await?;
    s.shutdown().await?;
    assert_closed_without_response(&mut s).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "aucune connexion upstream attendue");

    // Requête légitime : une seule connexion upstream, la sienne.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await?;
    let mut buf = Vec::new();
    let (head, body) = get(&mut s, &mut buf, "/TOK123/next", "").await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    assert_eq!(body, b"next-ok");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    // Requête suivante de la même connexion, sans token ni cookie : coupée.
    send_get(&mut s, "/next", "").await;
    assert_closed_without_response(&mut s).await;

    // Chaque refus est audité avec son motif ; les headers incomplets
    // (client parti) ne sont pas un refus.
    let mut rejections = token_rejections(&audit, 5).await;
    rejections.sort_by_key(|r| *r as u8);
    assert_eq!(
        rejections,
        [
            TokenRejection::InvalidToken,
            TokenRejection::InvalidToken,
            TokenRejection::InvalidToken,
            TokenRejection::InvalidToken,
            TokenRejection::NotHttp,
        ]
    );

    drop(idle);
    h.stop();
    let events = audit.0.lock().unwrap().clone();
    assert!(
        !events.iter().any(|e| matches!(e, ProxyEvent::BridgeFailed { .. })),
        "events: {events:?}"
    );
    Ok(())
}

/// Parcours webview : la page d'entrée porte le token et reçoit le cookie ;
/// les chemins absolus `/…` qui suivent passent grâce au cookie, que
/// l'upstream ne voit jamais. Un redémarrage du proxy invalide le cookie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_cookie_lets_absolute_paths_through() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let (upstream, _) = spawn_counting_server(&pki).await;
    let cfg = make_cfg(&pki, upstream, Some("TOK123"));
    let audit = Arc::new(CollectingAudit::default());
    let h = start_loopback(Arc::clone(&cfg), 0, 1234, Arc::new(NoUid), audit.clone() as Arc<dyn AuditLogger>).await?;

    let mut s = TcpStream::connect(("127.0.0.1", h.port())).await?;
    let mut buf = Vec::new();
    let (head, _) = get(&mut s, &mut buf, "/TOK123/next", "").await;
    let cookie = session_cookie(&head);
    assert!(cookie.starts_with("mtlsb_iso="), "{cookie}");

    // Nouvelle connexion, chemin absolu sans token : accepté via le cookie,
    // qui est retiré avant l'upstream (les autres cookies passent).
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).await?;
    let mut buf = Vec::new();
    let (head, body) = get(&mut s, &mut buf, "/cookie", &format!("Cookie: lang=fr; {cookie}\r\n")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "head: {head}");
    assert_eq!(String::from_utf8(body).unwrap(), "lang=fr", "Cookie vu par l'upstream");
    assert!(!head.contains("Set-Cookie"), "cookie valide : rien à reposer: {head}");
    // Même connexion keepalive : toujours accepté.
    let (_, body) = get(&mut s, &mut buf, "/cookie", &format!("Cookie: {cookie}\r\n")).await;
    assert!(body.is_empty(), "header Cookie retiré en entier");

    // Redémarrage : nouveau secret, l'ancien cookie ne vaut plus rien.
    h.stop();
    let h = start_loopback(cfg, 0, 1234, Arc::new(NoUid), audit as Arc<dyn AuditLogger>).await?;
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).await?;
    send_get(&mut s, "/next", &format!("Cookie: {cookie}\r\n")).await;
    assert_closed_without_response(&mut s).await;
    let mut s = TcpStream::connect(("127.0.0.1", h.port())).await?;
    let mut buf = Vec::new();
    let (head, _) = get(&mut s, &mut buf, "/TOK123/next", &format!("Cookie: {cookie}\r\n")).await;
    let renewed = session_cookie(&head);
    assert_ne!(renewed, cookie);
    h.stop();
    Ok(())
}

// --- Signature Keystore lente ---

/// Signer « Keystore » de test (clé en RAM) dont la prochaine signature
/// peut être bloquée jusqu'à libération, comme un TEE/StrongBox lent.
struct GatedSigner {
    key: Arc<dyn rustls::sign::SigningKey>,
    armed: AtomicBool,
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl KeystoreSigner for GatedSigner {
    fn sign(
        &self,
        _key_handle: String,
        scheme: TlsSignatureScheme,
        data: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, SignerError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            let _ = self.entered.send(());
            // Appel synchrone bloquant, comme le callback Kotlin.
            let _ = self.release.lock().unwrap().recv_timeout(Duration::from_secs(10));
        }
        self.key
            .choose_scheme(&[scheme_to_rustls(scheme)])
            .ok_or(SignerError::Unsupported)?
            .sign(&data)
            .map_err(|e| SignerError::Failed(e.to_string()))
    }

    fn supported_schemes(&self, _key_handle: String) -> Vec<TlsSignatureScheme> {
        vec![TlsSignatureScheme::EcdsaNistp256Sha256]
    }
}

/// Démarré comme depuis Kotlin (entrée FFI) : pendant qu'une nouvelle
/// connexion attend sa signature Keystore, une session déjà établie
/// continue d'être servie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_keystore_signature_does_not_stall_other_sessions() -> Result<()> {
    init_crypto_provider();
    let pki = build_pki();
    let (upstream, _) = spawn_counting_server(&pki).await;
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let signer = Arc::new(GatedSigner {
        key: aws_lc_rs::sign::any_supported_type(&parse_pkcs8(&pki.client_key_pem)).unwrap(),
        armed: AtomicBool::new(false),
        entered: entered_tx,
        release: Mutex::new(release_rx),
    });
    let spec = ProxyConfigSpec {
        id: "slow".into(),
        upstream_host: "localhost".into(),
        upstream_port: upstream,
        sni: Some("localhost".into()),
        cert_chain_pem: pki.client_chain_pem.clone(),
        ca_pem: pki.ca_pem.clone(),
        keystore_alias: "alias".into(),
        path_token: None,
        extra_canonical_hosts: Vec::new(),
    };
    let h = start_loopback_proxy(
        spec,
        0,
        1234,
        Arc::clone(&signer) as Arc<dyn KeystoreSigner>,
        Arc::new(NoUid),
        Arc::new(CollectingAudit::default()),
    )
    .await?;

    // Session B établie (signature immédiate).
    let mut b = TcpStream::connect(("127.0.0.1", h.port())).await?;
    let mut b_buf = Vec::new();
    let (_, body) = get(&mut b, &mut b_buf, "/next", "").await;
    assert_eq!(body, b"next-ok");

    // Connexion A : son handshake reste bloqué dans la signature.
    signer.armed.store(true, Ordering::SeqCst);
    let mut a = TcpStream::connect(("127.0.0.1", h.port())).await?;
    send_get(&mut a, "/next", "").await;
    tokio::time::timeout(Duration::from_secs(5), entered_rx.recv())
        .await
        .expect("la connexion A doit atteindre la signature");

    // B est toujours servie pendant ce temps.
    let res = tokio::time::timeout(Duration::from_secs(3), async {
        send_get(&mut b, "/next", "").await;
        read_response(&mut b, &mut b_buf).await
    })
    .await;
    release_tx.send(()).unwrap();
    let (_, body) = res
        .expect("session B bloquée par la signature de A")
        .expect("session B fermée");
    assert_eq!(body, b"next-ok");

    // A aboutit une fois la signature rendue.
    let mut a_buf = Vec::new();
    let (_, body) = tokio::time::timeout(Duration::from_secs(5), read_response(&mut a, &mut a_buf))
        .await
        .expect("la connexion A doit aboutir")
        .expect("connexion A fermée");
    assert_eq!(body, b"next-ok");
    h.stop();
    Ok(())
}
