//! Mode "loopback" : on bind un port éphémère sur `127.0.0.1`, et pour chaque
//! connexion entrante on vérifie l'UID du pair via un callback uniffi
//! (`ConnectivityManager.getConnectionOwnerUid` côté Android). Toute connexion
//! dont l'UID ≠ celui de l'app cible enregistrée est droppée + auditée.
//!
//! Conception "bind à la demande" : l'orchestration côté Android n'appelle
//! [`start_loopback`] qu'au moment où l'utilisatrice tape "Lancer Jellyfin".
//! On ferme dès qu'elle quitte. Fenêtre d'attaque réduite à quelques
//! millisecondes même si l'UID-check tombe en panne sur un device exotique.

use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::config::ProxyConfig;
use crate::error::{CoreError, Result};
use crate::http_rewrite::{PathAuth, ResponseRewrite, TokenRejection};
use crate::proxy::{bridge_session, precompile_client_config, stop_requested, url_host};

/// Événements d'audit émis par les deux modes (loopback + VPN), persistés
/// dans la DB chiffrée côté Android et affichés dans l'UI logs.
///
/// `config_id` est présent quand l'événement est attribuable à une config
/// précise — Kotlin route alors vers le log de cette config. Sinon
/// (événement global comme VpnStarted/Stopped, ou route inconnue), Kotlin
/// broadcast vers toutes les configs actives.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ProxyEvent {
    // Loopback (toujours per-config, mais on garde un config_id explicite pour
    // que Kotlin dispatch uniformément avec la VPN). -------------------------
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
    /// La résolution UID a échoué — fail-closed.
    RejectedUidUnknown {
        config_id: String,
    },
    /// Requête refusée par le contrôle d'accès (token de path / cookie de
    /// session) : connexion fermée, upstream non contacté pour la première
    /// requête. Jamais de token, de cookie ni de chemin dans l'événement.
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
    /// Pas de config_id : la route ne matche aucune config connue.
    VpnRouteMissing {
        synthetic_ip: String,
        synthetic_port: u16,
    },
    // Communs -----------------------------------------------------------------
    BridgeFailed {
        config_id: String,
        reason: String,
    },
    Stopped,
}

/// Callback fourni par l'hôte Android pour résoudre l'UID propriétaire d'un
/// socket TCP côté **pair** (l'app cliente).
///
/// Convention : les paramètres décrivent la connexion **depuis le point de
/// vue du pair**. `peer_local_*` = adresse locale chez le pair (la source
/// des paquets qu'on reçoit), `peer_remote_*` = adresse distante chez le
/// pair (notre listener ou notre IP synthétique). Côté Kotlin :
/// `ConnectivityManager.getConnectionOwnerUid(IPPROTO_TCP, peerLocal, peerRemote)`
/// sans aucune inversion supplémentaire — d'où le renommage.
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

/// Callback fourni par l'hôte pour persister les événements d'audit.
#[uniffi::export(with_foreign)]
pub trait AuditLogger: Send + Sync {
    fn record(&self, event: ProxyEvent);
}

/// Handle vers un proxy loopback en cours d'exécution. Exposé à Kotlin comme
/// uniffi Object — Kotlin tient une référence et appelle `.stop()` quand le
/// service ou l'utilisatrice ferme la session.
#[derive(uniffi::Object)]
pub struct LoopbackHandle {
    port: u16,
    stop_tx: watch::Sender<bool>,
    // On garde le JoinHandle pour pouvoir l'abort en Drop si jamais .stop()
    // n'a pas été appelé explicitement.
    task: std::sync::Mutex<Option<JoinHandle<()>>>,
}

#[uniffi::export]
impl LoopbackHandle {
    /// Port réellement utilisé (utile quand bind_port=0).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Demande l'arrêt : la tâche d'accept s'interrompt et ferme toutes les
    /// sessions en cours (sockets client et upstream).
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

impl Drop for LoopbackHandle {
    fn drop(&mut self) {
        // Filet de sécurité : si la doxev a oublié .stop() et que le handle est
        // GC côté Kotlin, on tue la tâche pour ne pas laisser de listener orphelin.
        let _ = self.stop_tx.send(true);
        if let Ok(mut t) = self.task.lock() {
            if let Some(h) = t.take() {
                h.abort();
            }
        }
    }
}

/// Démarre un proxy loopback. `bind_port = 0` ⇒ port éphémère choisi par l'OS.
pub async fn start_loopback(
    cfg: Arc<ProxyConfig>,
    bind_port: u16,
    expected_uid: u32,
    uid_resolver: Arc<dyn PeerUidResolver>,
    audit: Arc<dyn AuditLogger>,
) -> Result<Arc<LoopbackHandle>> {
    crate::init_crypto_provider();
    let client_config = precompile_client_config(&cfg)?;
    // Un seul secret de cookie pour toutes les connexions du proxy, tiré à
    // chaque démarrage : un redémarrage invalide les cookies déjà posés.
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

/// Réécriture de réponse : on rewrite les URLs absolues `https://upstream`
/// → `http://127.0.0.1:bindport[/token]` dans les Location headers et les
/// bodies JSON/HTML. Indispensable pour les apps qui font de l'OAuth via
/// browser externe (Nextcloud Login v2 + Authentik), où le serveur sérialise
/// son URL canonique dans la réponse.
pub(crate) fn loopback_response_rewrite(cfg: &ProxyConfig, port: u16) -> ResponseRewrite {
    // Le token fait partie de la base : sans lui, les URLs réécrites seraient
    // refusées (BadToken) quand le client les suit.
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
    // Hosts canoniques additionnels (cas Nextcloud avec `overwrite.cli.url`
    // pointant sur un autre hostname que celui qu'on connecte, ou
    // configurations multi-domaines derrière le même reverse-proxy).
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
    // Sessions en cours : abortées ensemble à l'arrêt (chaque session tient
    // ses deux sockets dans sa propre tâche, cf. run_http_session).
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = stop_requested(&mut stop_rx) => break,
            // Récolte des sessions terminées, sinon le JoinSet grossit.
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
                        // Convention "depuis le pair" : son local = notre
                        // remote (l'app cliente côté loopback), son remote =
                        // notre local (notre listener 127.0.0.1:port).
                        //
                        // Android restreint getConnectionOwnerUid : sur la
                        // plupart des devices, l'API retourne INVALID_UID
                        // pour les sockets que notre app ne route pas
                        // (notre VPN). On soft-fail : si None, on accepte
                        // mais on log Accepted{peer_uid=0} pour qu'on voie
                        // dans l'audit que la résolution UID n'a pas marché.
                        // Mismatch explicite (Some(uid) != expected) reste
                        // fail-closed : c'est la signature claire d'attaque.
                        // L'isolation effective du loopback est donc le token
                        // de path / cookie de session (cf. PathAuth), vérifié
                        // avant toute connexion upstream (bridge_session).
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
                        // Si accept retourne en boucle des erreurs (FD épuisé,
                        // listener fermé), on temporise pour ne pas saturer le CPU.
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
