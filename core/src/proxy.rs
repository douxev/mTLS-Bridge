use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::config::ProxyConfig;
use crate::error::{CoreError, Result};
use crate::http_rewrite::{
    http_request_pipe, http_response_pipe, read_first_request, token_rejection, PathAuth,
    RequestMeta, ResponseRewrite, TokenRejection,
};
use crate::tls::build_client_config;

/// Durée max d'un TCP connect upstream. Sans ça, un backend injoignable
/// fait pendre la connexion ~75 s (timeout OS Linux) avant d'échouer —
/// l'app cliente abandonne avant et on n'a rien dans les logs.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Durée max d'un handshake TLS upstream. mTLS implique parfois plusieurs
/// allers-retours signés par Keystore → plus large que pour du TLS classique.
const UPSTREAM_TLS_TIMEOUT: Duration = Duration::from_secs(15);

/// Une session sans aucun octet échangé, dans un sens comme dans l'autre,
/// pendant ce délai est fermée : borne les sockets et sessions TLS orphelines
/// quand le client ou l'upstream disparaît sans FIN (réseau mobile, app tuée).
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Hôte sans crochets, pour le connect et le SNI (`[::1]` → `::1`).
fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Hôte tel qu'il s'écrit dans une URL ou un header `Host:` : IPv6 littérale
/// entre crochets.
pub(crate) fn url_host(host: &str) -> String {
    let bare = bare_host(host);
    if bare.contains(':') {
        format!("[{bare}]")
    } else {
        bare.to_string()
    }
}

/// Pont bidirectionnel entre une socket entrante (en clair) et un upstream mTLS.
///
/// L'app cible parle HTTP/1.1 en clair côté entrée, c'est rustls qui chiffre
/// en sortie avec le client cert. Voir [`bridge_session`].
///
/// Générique en `S` pour accepter `tokio::net::TcpStream` (mode loopback) et
/// `netstack_smoltcp::TcpStream` (mode VPN). Les deux implémentent
/// AsyncRead+AsyncWrite.
///
/// Le cookie de session du token (cf. [`PathAuth`]) n'a ici de portée que
/// la connexion : le mode loopback partage un [`PathAuth`] entre toutes ses
/// connexions via [`bridge_session`].
pub async fn bridge_to_mtls_upstream<S>(
    inbound: S,
    client_config: Arc<ClientConfig>,
    cfg: &ProxyConfig,
    response_rewrite: Option<ResponseRewrite>,
) -> Result<()>
where
    // Send + 'static : l'appelant spawn la session entière comme une tâche.
    // TcpStream et netstack_smoltcp::TcpStream satisfont déjà.
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let auth = cfg
        .path_token
        .as_deref()
        .map(|t| PathAuth::new(t, &cfg.id))
        .transpose()?;
    bridge_session(inbound, client_config, cfg, auth.as_ref(), response_rewrite.as_ref())
        .await
        .map(|_| ())
}

/// Session d'un client : la première requête est lue et validée (token ou
/// cookie de session) AVANT d'ouvrir la connexion upstream. Sinon n'importe
/// quel client local déclenchait un connect + handshake mTLS — donc une
/// signature avec la clé Keystore — sans le moindre contrôle.
///
/// `Ok(Some(_))` : session coupée par le contrôle d'accès, que l'appelant
/// audite.
pub(crate) async fn bridge_session<S>(
    mut inbound: S,
    client_config: Arc<ClientConfig>,
    cfg: &ProxyConfig,
    auth: Option<&PathAuth>,
    response_rewrite: Option<&ResponseRewrite>,
) -> Result<Option<TokenRejection>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first = tokio::time::timeout(IDLE_TIMEOUT, read_first_request(&mut inbound, auth)).await;
    let prefix = match first {
        Ok(Ok(Some(prefix))) => prefix,
        // Fermé avant une requête complète : rien à transmettre.
        Ok(Ok(None)) => return Ok(None),
        Ok(Err(e)) => {
            if !is_benign_eof(&e) {
                log::warn!("bridge {}: {e}, upstream non contacté", cfg.id);
            }
            return Ok(token_rejection(&e));
        }
        Err(_) => {
            log::info!(
                "bridge {}: aucune requête en {}s, fermeture",
                cfg.id,
                IDLE_TIMEOUT.as_secs(),
            );
            return Ok(None);
        }
    };

    let upstream = connect_upstream(client_config, cfg).await?;
    log::info!("bridge {}: TLS OK, démarrage pipe per-request", cfg.id);
    Ok(run_http_session(
        inbound,
        prefix,
        upstream,
        &url_host(&cfg.upstream_host),
        auth,
        response_rewrite,
        IDLE_TIMEOUT,
        &cfg.id,
    )
    .await)
}

/// TCP connect + handshake mTLS vers l'upstream, bornés en temps.
async fn connect_upstream(
    client_config: Arc<ClientConfig>,
    cfg: &ProxyConfig,
) -> Result<TlsStream<TcpStream>> {
    let host = bare_host(&cfg.upstream_host);
    let sni = cfg.sni.clone().unwrap_or_else(|| host.to_string());
    let server_name = ServerName::try_from(sni.clone())
        .map_err(|e| CoreError::Config(format!("SNI invalide ({sni}): {e}")))?;

    let upstream_addr = format!("{}:{}", url_host(host), cfg.upstream_port);
    log::info!("bridge {}: TCP connect {}", cfg.id, upstream_addr);
    // Tuple (host, port) et non la chaîne `host:port` : une IPv6 littérale
    // (`::1`, `2001:db8::1`) ne se parse pas sans crochets.
    let tcp = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect((host, cfg.upstream_port)),
    )
    .await
    .map_err(|_| CoreError::Io(format!(
        "TCP connect timeout après {}s vers {upstream_addr}",
        UPSTREAM_CONNECT_TIMEOUT.as_secs(),
    )))??;
    // Pas de Nagle : on veut que les petits paquets HTTP partent immédiatement.
    tcp.set_nodelay(true)?;
    log::info!("bridge {}: TCP OK, TLS handshake (SNI={sni})", cfg.id);

    let connector = TlsConnector::from(client_config);
    let upstream = tokio::time::timeout(
        UPSTREAM_TLS_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| CoreError::Tls(format!(
        "TLS handshake timeout après {}s",
        UPSTREAM_TLS_TIMEOUT.as_secs(),
    )))??;
    Ok(upstream)
}

/// Pilote une session HTTP/1.1 client ↔ upstream :
/// - client→upstream passe par le pipe de requête (réécrit le Host header de
///   CHAQUE requête HTTP/1.1 — indispensable derrière un reverse-proxy
///   Caddy/Nginx qui route par Host, sinon les requêtes keepalive après le
///   splash retombent en 404 — et vérifie/retire le token de path ou le
///   cookie de session),
/// - upstream→client passe par le pipe de réponse si `response_rewrite`
///   (mode loopback), sinon en copie brute (mode VPN).
///
/// `client_prefix` : octets déjà lus sur `client` (la première requête, lue
/// avant la connexion upstream).
///
/// Les deux sens tournent dans la tâche appelante (pas de spawn) : annuler
/// cette tâche ferme les deux sockets. La session se termine aussi après
/// `idle_timeout` sans aucun trafic.
///
/// Renvoie le motif du refus si une requête de la session a été rejetée par
/// le contrôle d'accès (token / cookie).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_http_session<C, U>(
    client: C,
    client_prefix: Vec<u8>,
    upstream: U,
    upstream_host: &str,
    auth: Option<&PathAuth>,
    response_rewrite: Option<&ResponseRewrite>,
    idle_timeout: Duration,
    id: &str,
) -> Option<TokenRejection>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(Activity::new());
    let (in_rd, mut in_wr) = tokio::io::split(Tracked::new(client, Arc::clone(&activity)));
    let (mut up_rd, up_wr) = tokio::io::split(Tracked::new(upstream, Arc::clone(&activity)));
    // Infos de chaque requête, dans l'ordre : le pipe de réponse en a besoin
    // pour savoir si un Content-Length annonce vraiment un body (HEAD) et
    // s'il doit poser le cookie de session.
    let (meta_tx, meta_rx) = mpsc::unbounded_channel::<RequestMeta>();

    // Renvoie le motif du refus si la session doit être coupée sans attendre
    // la réponse.
    let req = async move {
        // Sans pipe de réponse (copie brute), personne ne lirait la file.
        let rewrites_responses = response_rewrite.is_some();
        let meta_tx = response_rewrite.map(|_| meta_tx);
        let res = http_request_pipe(
            in_rd,
            client_prefix,
            up_wr,
            upstream_host,
            auth,
            meta_tx,
            rewrites_responses,
        )
        .await;
        match res {
            Ok(()) => None,
            Err(e) => {
                if !is_benign_eof(&e) {
                    log::warn!("bridge {id}: req pipe err: {e}");
                }
                // Refus (token…) : l'upstream n'a rien reçu et ne répondra
                // pas, inutile de garder le client en attente.
                token_rejection(&e)
            }
        }
    };
    let resp = async move {
        let res = match response_rewrite {
            // Pipe HTTP/1.1 per-response : réécrit les URLs absolues qui
            // leakent depuis l'upstream (Location + bodies textuels).
            // Indispensable pour les flows OAuth qui sérialisent l'URL
            // upstream canonique dans le body ou les redirects.
            Some(rw) => http_response_pipe(&mut up_rd, &mut in_wr, rw, meta_rx).await,
            None => tokio::io::copy(&mut up_rd, &mut in_wr).await.map(|_| ()),
        };
        match res {
            Ok(()) => {
                let _ = in_wr.shutdown().await;
            }
            Err(e) if is_benign_eof(&e) => {}
            Err(e) => log::warn!("bridge {id}: resp pipe err: {e}"),
        }
    };
    let pipes = async move {
        tokio::pin!(req, resp);
        let req_first = tokio::select! {
            rejected = &mut req => Some(rejected),
            () = &mut resp => None,
        };
        // Un EOF d'un côté ne suffit pas à clore l'autre direction (cas
        // réponse longue après FIN client).
        match req_first {
            Some(None) => {
                resp.await;
                None
            }
            Some(rejected) => rejected,
            None => req.await,
        }
    };
    tokio::select! {
        rejected = pipes => rejected,
        () = idle_watchdog(&activity, idle_timeout) => {
            log::info!(
                "bridge {id}: aucune activité depuis {}s, fermeture",
                idle_timeout.as_secs(),
            );
            None
        }
    }
}

/// Résout quand l'arrêt est demandé (`true`) ou que l'émetteur a disparu
/// (handle droppé).
pub(crate) async fn stop_requested(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Instant du dernier octet lu ou écrit sur une session, dans un sens ou
/// dans l'autre.
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        self.start
            .elapsed()
            .saturating_sub(Duration::from_millis(self.last_ms.load(Ordering::Relaxed)))
    }
}

/// Résout après `timeout` sans activité. Un réveil par période au plus.
async fn idle_watchdog(activity: &Activity, timeout: Duration) {
    loop {
        let idle = activity.idle_for();
        if idle >= timeout {
            return;
        }
        tokio::time::sleep(timeout - idle).await;
    }
}

/// Stream qui horodate chaque lecture/écriture non vide dans [`Activity`].
struct Tracked<T> {
    inner: T,
    activity: Arc<Activity>,
}

impl<T> Tracked<T> {
    fn new(inner: T, activity: Arc<Activity>) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Tracked<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        res
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Tracked<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(res, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        res
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if matches!(res, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn is_benign_eof(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
    )
}

/// Construit le `ClientConfig` rustls une fois pour toutes : le handshake TLS
/// rejouera à chaque connexion, mais la racine de confiance et la chaîne client
/// sont coûteuses à parser. L'appelant cache `Arc<ClientConfig>`.
pub fn precompile_client_config(cfg: &ProxyConfig) -> Result<Arc<ClientConfig>> {
    build_client_config(cfg)
}
