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

/// Maximum duration of an upstream TCP connect. Without it, an unreachable
/// backend leaves the connection hanging for ~75 s (Linux OS timeout) before
/// failing: the client app gives up first and nothing shows up in the logs.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum duration of an upstream TLS handshake. mTLS sometimes involves
/// several round trips signed by the Keystore -> longer than for plain TLS.
const UPSTREAM_TLS_TIMEOUT: Duration = Duration::from_secs(15);

/// A session with no byte exchanged, in either direction, for this long is
/// closed: this bounds orphaned sockets and TLS sessions when the client or
/// the upstream disappears without a FIN (mobile network, killed app).
const IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Host without brackets, for the connect and the SNI (`[::1]` -> `::1`).
fn bare_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Host as written in a URL or a `Host:` header: IPv6 literal in brackets.
pub(crate) fn url_host(host: &str) -> String {
    let bare = bare_host(host);
    if bare.contains(':') {
        format!("[{bare}]")
    } else {
        bare.to_string()
    }
}

/// Bidirectional bridge between an incoming (plaintext) socket and an mTLS upstream.
///
/// The target app speaks plaintext HTTP/1.1 on the inbound side; rustls
/// encrypts on the outbound side with the client cert. See [`bridge_session`].
///
/// Generic over `S` to accept both `tokio::net::TcpStream` (loopback mode) and
/// `netstack_smoltcp::TcpStream` (VPN mode). Both implement
/// AsyncRead+AsyncWrite.
///
/// The token session cookie (see [`PathAuth`]) is scoped to the connection
/// here: loopback mode shares one [`PathAuth`] across all its connections
/// through [`bridge_session`].
pub async fn bridge_to_mtls_upstream<S>(
    inbound: S,
    client_config: Arc<ClientConfig>,
    cfg: &ProxyConfig,
    response_rewrite: Option<ResponseRewrite>,
) -> Result<()>
where
    // Send + 'static: the caller spawns the whole session as a task.
    // TcpStream and netstack_smoltcp::TcpStream already satisfy this.
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let auth = cfg
        .path_token
        .as_deref()
        .map(|t| PathAuth::new(t, &cfg.id))
        .transpose()?;
    bridge_session(
        inbound,
        client_config,
        cfg,
        auth.as_ref(),
        response_rewrite.as_ref(),
    )
    .await
    .map(|_| ())
}

/// A client session: the first request is read and validated (token or
/// session cookie) BEFORE the upstream connection is opened. Otherwise any
/// local client could trigger a connect + mTLS handshake (and therefore a
/// signature with the Keystore key) without any check.
///
/// `Ok(Some(_))`: session cut by access control, which the caller audits.
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
        // Closed before a complete request: nothing to forward.
        Ok(Ok(None)) => return Ok(None),
        Ok(Err(e)) => {
            if !is_benign_eof(&e) {
                log::warn!("bridge {}: {e}, upstream not contacted", cfg.id);
            }
            return Ok(token_rejection(&e));
        }
        Err(_) => {
            log::info!(
                "bridge {}: no request within {}s, closing",
                cfg.id,
                IDLE_TIMEOUT.as_secs(),
            );
            return Ok(None);
        }
    };

    let upstream = connect_upstream(client_config, cfg).await?;
    log::info!("bridge {}: TLS OK, starting per-request pipe", cfg.id);
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

/// TCP connect + mTLS handshake to the upstream, both time-bounded.
async fn connect_upstream(
    client_config: Arc<ClientConfig>,
    cfg: &ProxyConfig,
) -> Result<TlsStream<TcpStream>> {
    let host = bare_host(&cfg.upstream_host);
    let sni = cfg.sni.clone().unwrap_or_else(|| host.to_string());
    let server_name = ServerName::try_from(sni.clone())
        .map_err(|e| CoreError::Config(format!("invalid SNI ({sni}): {e}")))?;

    let upstream_addr = format!("{}:{}", url_host(host), cfg.upstream_port);
    log::info!("bridge {}: TCP connect {}", cfg.id, upstream_addr);
    // A (host, port) tuple rather than the `host:port` string: an IPv6
    // literal (`::1`, `2001:db8::1`) does not parse without brackets.
    let tcp = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect((host, cfg.upstream_port)),
    )
    .await
    .map_err(|_| {
        CoreError::Io(format!(
            "TCP connect timeout after {}s to {upstream_addr}",
            UPSTREAM_CONNECT_TIMEOUT.as_secs(),
        ))
    })??;
    // No Nagle: small HTTP packets must go out immediately.
    tcp.set_nodelay(true)?;
    log::info!("bridge {}: TCP OK, TLS handshake (SNI={sni})", cfg.id);

    let connector = TlsConnector::from(client_config);
    let upstream = tokio::time::timeout(UPSTREAM_TLS_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| {
            CoreError::Tls(format!(
                "TLS handshake timeout after {}s",
                UPSTREAM_TLS_TIMEOUT.as_secs(),
            ))
        })??;
    Ok(upstream)
}

/// Drives a client <-> upstream HTTP/1.1 session:
/// - client->upstream goes through the request pipe (rewrites the Host header
///   of EVERY HTTP/1.1 request, which is required behind a Caddy/Nginx
///   reverse proxy that routes by Host, otherwise keep-alive requests after
///   the splash fall back to 404; it also checks/strips the path token or the
///   session cookie),
/// - upstream->client goes through the response pipe when `response_rewrite`
///   is set (loopback mode), otherwise as a raw copy (VPN mode).
///
/// `client_prefix`: bytes already read from `client` (the first request, read
/// before the upstream connection).
///
/// Both directions run in the calling task (no spawn): cancelling that task
/// closes both sockets. The session also ends after `idle_timeout` without
/// any traffic.
///
/// Returns the rejection reason if a request of the session was refused by
/// access control (token / cookie).
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
    // Per-request info, in order: the response pipe needs it to know whether
    // a Content-Length really announces a body (HEAD) and whether it must set
    // the session cookie.
    let (meta_tx, meta_rx) = mpsc::unbounded_channel::<RequestMeta>();

    // Returns the rejection reason if the session must be cut without waiting
    // for the response.
    let req = async move {
        // Without a response pipe (raw copy), nobody would read the queue.
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
                // Rejection (token, etc.): the upstream received nothing and
                // will not answer, no point keeping the client waiting.
                token_rejection(&e)
            }
        }
    };
    let resp = async move {
        let res = match response_rewrite {
            // Per-response HTTP/1.1 pipe: rewrites the absolute URLs that
            // leak from the upstream (Location + text bodies). Required for
            // OAuth flows that serialize the canonical upstream URL in the
            // body or in redirects.
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
        // An EOF on one side is not enough to close the other direction (a
        // long response after the client's FIN).
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
                "bridge {id}: no activity for {}s, closing",
                idle_timeout.as_secs(),
            );
            None
        }
    }
}

/// Resolves when a stop is requested (`true`) or when the sender is gone
/// (handle dropped).
pub(crate) async fn stop_requested(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Time of the last byte read or written on a session, in either direction.
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

/// Resolves after `timeout` without activity. At most one wake-up per period.
async fn idle_watchdog(activity: &Activity, timeout: Duration) {
    loop {
        let idle = activity.idle_for();
        if idle >= timeout {
            return;
        }
        tokio::time::sleep(timeout - idle).await;
    }
}

/// Stream that timestamps every non-empty read/write in [`Activity`].
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

/// Builds the rustls `ClientConfig` once and for all: the TLS handshake is
/// replayed on every connection, but the trust root and the client chain are
/// expensive to parse. The caller caches the `Arc<ClientConfig>`.
pub fn precompile_client_config(cfg: &ProxyConfig) -> Result<Arc<ClientConfig>> {
    build_client_config(cfg)
}
