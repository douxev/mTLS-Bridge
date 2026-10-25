//! "Loopback" mode: an ephemeral port is bound on `127.0.0.1`, and for every
//! incoming connection the peer UID is checked through a uniffi callback
//! (`ConnectivityManager.getConnectionOwnerUid` on the Android side). Any
//! connection whose UID differs from that of the registered target app is
//! dropped and audited.
//!
//! "Bind on demand" design: the Android orchestration only calls
//! [`start_loopback`] when the user taps "Launch Jellyfin", and the proxy is
//! closed as soon as they leave. The attack window shrinks to a few
//! milliseconds even if the UID check breaks on an unusual device.

use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::config::ProxyConfig;
use crate::error::{CoreError, Result};
use crate::http_rewrite::{PathAuth, ResponseRewrite, TokenRejection};
use crate::proxy::{bridge_session, precompile_client_config, stop_requested, url_host};

/// Audit events emitted by both modes (loopback + VPN), persisted in the
/// encrypted database on the Android side and shown in the logs UI.
///
/// `config_id` is present when the event can be attributed to a specific
/// config: Kotlin then routes it to that config's log. Otherwise (a global
/// event such as VpnStarted/Stopped, or an unknown route), Kotlin broadcasts
/// it to every active config.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ProxyEvent {
    // Loopback (always per config, but an explicit config_id is kept so that
    // Kotlin dispatches the same way as for the VPN). -------------------------
    BindOk {
        config_id: String,
        port: u16,
    },
    BindFailed {
        config_id: String,
        reason: String,
    },
    Accepted {
        config_id: String,
        peer_uid: u32,
    },
    RejectedUidMismatch {
        config_id: String,
        peer_uid: u32,
        expected_uid: u32,
    },
    /// UID resolution failed: fail-closed.
    RejectedUidUnknown {
        config_id: String,
    },
    /// Request refused by access control (path token / session cookie): the
    /// connection is closed and the upstream is not contacted for the first
    /// request. The event never contains a token, cookie or path.
    RejectedToken {
        config_id: String,
        reason: TokenRejection,
    },
    // VPN ---------------------------------------------------------------------
    VpnStarted {
        route_count: u32,
    },
    VpnRouteHit {
        config_id: String,
        synthetic_ip: String,
        synthetic_port: u16,
    },
    /// No config_id: the route matches no known config.
    VpnRouteMissing {
        synthetic_ip: String,
        synthetic_port: u16,
    },
    // Common ------------------------------------------------------------------
    BridgeFailed {
        config_id: String,
        reason: String,
    },
    Stopped,
}

/// Callback provided by the Android host to resolve the owner UID of a TCP
/// socket on the **peer** side (the client app).
///
/// Convention: the parameters describe the connection **from the peer's
/// point of view**. `peer_local_*` = local address on the peer (the source of
/// the packets received here), `peer_remote_*` = remote address on the peer
/// (our listener or our synthetic IP). On the Kotlin side:
/// `ConnectivityManager.getConnectionOwnerUid(IPPROTO_TCP, peerLocal, peerRemote)`
/// with no further swapping, hence the naming.
#[uniffi::export(with_foreign)]
pub trait PeerUidResolver: Send + Sync {
    fn peer_uid(
        &self,
        peer_local_ip: String,
        peer_local_port: u16,
        peer_remote_ip: String,
        peer_remote_port: u16,
    ) -> Option<u32>;
}

/// Callback provided by the host to persist audit events.
#[uniffi::export(with_foreign)]
pub trait AuditLogger: Send + Sync {
    fn record(&self, event: ProxyEvent);
}

/// Handle to a running loopback proxy. Exported to Kotlin as a uniffi Object:
/// Kotlin holds a reference and calls `.stop()` when the service or the user
/// closes the session.
#[derive(uniffi::Object)]
pub struct LoopbackHandle {
    port: u16,
    stop_tx: watch::Sender<bool>,
    // The JoinHandle is kept so it can be aborted in Drop if .stop() was
    // never called explicitly.
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl LoopbackHandle {
    /// Port actually in use (useful when bind_port=0).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Requests a stop: the accept task stops and closes every ongoing
    /// session (client and upstream sockets).
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

impl Drop for LoopbackHandle {
    fn drop(&mut self) {
        // Safety net: if .stop() was never called and the handle is garbage
        // collected on the Kotlin side, kill the task so no orphan listener is left.
        let _ = self.stop_tx.send(true);
        if let Ok(mut t) = self.task.lock() {
            if let Some(h) = t.take() {
                h.abort();
            }
        }
    }
}

/// Starts a loopback proxy. `bind_port = 0` -> ephemeral port chosen by the OS.
pub async fn start_loopback(
    cfg: Arc<ProxyConfig>,
    bind_port: u16,
    expected_uid: u32,
    uid_resolver: Arc<dyn PeerUidResolver>,
    audit: Arc<dyn AuditLogger>,
) -> Result<Arc<LoopbackHandle>> {
    crate::init_crypto_provider();
    let client_config = precompile_client_config(&cfg)?;
    // A single cookie secret for every connection of the proxy, drawn at each
    // start: a restart invalidates the cookies already set.
    let auth = match cfg.path_token.as_deref() {
        Some(token) => Some(Arc::new(PathAuth::new(token, &cfg.id)?)),
        None => None,
    };

    let listener = match TcpListener::bind(("127.0.0.1", bind_port)).await {
        Ok(l) => l,
        Err(e) => {
            audit.record(ProxyEvent::BindFailed {
                config_id: cfg.id.clone(),
                reason: e.to_string(),
            });
            return Err(CoreError::Io(e.to_string()));
        }
    };
    let actual_port = listener.local_addr()?.port();
    audit.record(ProxyEvent::BindOk {
        config_id: cfg.id.clone(),
        port: actual_port,
    });

    let response_rewrite = loopback_response_rewrite(&cfg, actual_port);

    let (stop_tx, stop_rx) = watch::channel(false);
    let cfg_for_task = Arc::clone(&cfg);
    let audit_for_task = Arc::clone(&audit);
    let uid_for_task = Arc::clone(&uid_resolver);

    let task = tokio::spawn(async move {
        accept_loop(
            listener,
            cfg_for_task,
            client_config,
            expected_uid,
            uid_for_task,
            audit_for_task.clone(),
            stop_rx,
            auth,
            response_rewrite,
        )
        .await;
        audit_for_task.record(ProxyEvent::Stopped);
    });

    Ok(Arc::new(LoopbackHandle {
        port: actual_port,
        stop_tx,
        task: std::sync::Mutex::new(Some(task)),
    }))
}

/// Response rewriting: absolute URLs `https://upstream` are rewritten to
/// `http://127.0.0.1:bindport[/token]` in Location headers and in JSON/HTML
/// bodies. Required for apps that do OAuth through an external browser
/// (Nextcloud Login v2 + Authentik), where the server serializes its
/// canonical URL in the response.
pub(crate) fn loopback_response_rewrite(cfg: &ProxyConfig, port: u16) -> ResponseRewrite {
    // The token is part of the base: without it, the rewritten URLs would be
    // refused (BadToken) when the client follows them.
    let to_url = match cfg.path_token.as_deref() {
        Some(token) if !token.is_empty() => format!("http://127.0.0.1:{port}/{token}"),
        _ => format!("http://127.0.0.1:{port}"),
    };
    let host = url_host(&cfg.upstream_host);
    let mut from_urls = vec![if cfg.upstream_port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{}", cfg.upstream_port)
    }];
    // Additional canonical hosts (Nextcloud with an `overwrite.cli.url`
    // pointing to a hostname other than the one connected to, or multi-domain
    // setups behind the same reverse proxy).
    for h in &cfg.extra_canonical_hosts {
        if !h.is_empty() {
            from_urls.push(format!("https://{h}"));
        }
    }
    ResponseRewrite { from_urls, to_url }
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    listener: TcpListener,
    cfg: Arc<ProxyConfig>,
    client_config: Arc<rustls::ClientConfig>,
    expected_uid: u32,
    uid_resolver: Arc<dyn PeerUidResolver>,
    audit: Arc<dyn AuditLogger>,
    mut stop_rx: watch::Receiver<bool>,
    auth: Option<Arc<PathAuth>>,
    response_rewrite: ResponseRewrite,
) {
    // Ongoing sessions: aborted together on stop (each session holds its two
    // sockets in its own task, see run_http_session).
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = stop_requested(&mut stop_rx) => break,
            // Reap finished sessions, otherwise the JoinSet keeps growing.
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            res = listener.accept() => {
                match res {
                    Ok((stream, remote)) => {
                        let local = match stream.local_addr() {
                            Ok(a) => a,
                            Err(e) => {
                                audit.record(ProxyEvent::BridgeFailed {
                                    config_id: cfg.id.clone(),
                                    reason: format!("local_addr: {e}"),
                                });
                                continue;
                            }
                        };
                        // "From the peer" convention: its local = our remote
                        // (the client app on the loopback side), its remote =
                        // our local (our 127.0.0.1:port listener).
                        //
                        // Android restricts getConnectionOwnerUid: on most
                        // devices, the API returns INVALID_UID for sockets
                        // that our app does not route (through our VPN). This
                        // soft-fails: on None, the connection is accepted but
                        // logged as Accepted{peer_uid=0}, so the audit shows
                        // that UID resolution did not work. An explicit
                        // mismatch (Some(uid) != expected) stays fail-closed:
                        // that is a clear attack signature. The effective
                        // isolation of the loopback is therefore the path
                        // token / session cookie (see PathAuth), checked
                        // before any upstream connection (bridge_session).
                        let uid_opt = crate::runtime::blocking(|| {
                            uid_resolver.peer_uid(
                                remote.ip().to_string(),
                                remote.port(),
                                local.ip().to_string(),
                                local.port(),
                            )
                        });
                        match uid_opt {
                            None => {
                                log::debug!(
                                    "loopback {}: getConnectionOwnerUid INVALID, soft-accept",
                                    cfg.id,
                                );
                                audit.record(ProxyEvent::Accepted {
                                    config_id: cfg.id.clone(),
                                    peer_uid: 0,
                                });
                                spawn_session(&mut sessions, stream, &cfg, &client_config, &audit, &auth, &response_rewrite);
                                continue;
                            }
                            Some(uid) if uid != expected_uid => {
                                audit.record(ProxyEvent::RejectedUidMismatch {
                                    config_id: cfg.id.clone(),
                                    peer_uid: uid,
                                    expected_uid,
                                });
                                drop(stream);
                            }
                            Some(uid) => {
                                audit.record(ProxyEvent::Accepted {
                                    config_id: cfg.id.clone(),
                                    peer_uid: uid,
                                });
                                spawn_session(&mut sessions, stream, &cfg, &client_config, &audit, &auth, &response_rewrite);
                            }
                        }
                    }
                    Err(e) => {
                        audit.record(ProxyEvent::BridgeFailed {
                            config_id: cfg.id.clone(),
                            reason: format!("accept: {e}"),
                        });
                        // If accept keeps returning errors (FDs exhausted,
                        // listener closed), back off so as not to saturate the CPU.
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    sessions.shutdown().await;
}

fn spawn_session(
    sessions: &mut JoinSet<()>,
    stream: TcpStream,
    cfg: &Arc<ProxyConfig>,
    client_config: &Arc<rustls::ClientConfig>,
    audit: &Arc<dyn AuditLogger>,
    auth: &Option<Arc<PathAuth>>,
    response_rewrite: &ResponseRewrite,
) {
    let cfg = Arc::clone(cfg);
    let client_config = Arc::clone(client_config);
    let audit = Arc::clone(audit);
    let auth = auth.clone();
    let rw = response_rewrite.clone();
    sessions.spawn(async move {
        match bridge_session(stream, client_config, &cfg, auth.as_deref(), Some(&rw)).await {
            Ok(None) => {}
            Ok(Some(reason)) => audit.record(ProxyEvent::RejectedToken {
                config_id: cfg.id.clone(),
                reason,
            }),
            Err(e) => audit.record(ProxyEvent::BridgeFailed {
                config_id: cfg.id.clone(),
                reason: e.to_string(),
            }),
        }
    });
}
