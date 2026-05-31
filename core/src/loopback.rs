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

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::ProxyConfig;
use crate::error::{CoreError, Result};
use crate::proxy::{bridge_to_mtls_upstream, precompile_client_config};

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
    BindOk { config_id: String, port: u16 },
    BindFailed { config_id: String, reason: String },
    Accepted { config_id: String, peer_uid: u32 },
    RejectedUidMismatch { config_id: String, peer_uid: u32, expected_uid: u32 },
    /// La résolution UID a échoué — fail-closed.
    RejectedUidUnknown { config_id: String },
    // VPN ---------------------------------------------------------------------
    VpnStarted { route_count: u32 },
    VpnRouteHit { config_id: String, synthetic_ip: String, synthetic_port: u16 },
    /// Pas de config_id : la route ne matche aucune config connue.
    VpnRouteMissing { synthetic_ip: String, synthetic_port: u16 },
    // Communs -----------------------------------------------------------------
    BridgeFailed { config_id: String, reason: String },
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

    /// Demande l'arrêt propre. La tâche d'accept va s'interrompre à la
    /// prochaine itération. Les sessions en cours continuent leur cycle naturel.
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

async fn accept_loop(
    listener: TcpListener,
    cfg: Arc<ProxyConfig>,
    client_config: Arc<rustls::ClientConfig>,
    expected_uid: u32,
    uid_resolver: Arc<dyn PeerUidResolver>,
    audit: Arc<dyn AuditLogger>,
    mut stop_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() { break; }
            }
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
                        let uid_opt = uid_resolver.peer_uid(
                            remote.ip().to_string(),
                            remote.port(),
                            local.ip().to_string(),
                            local.port(),
                        );
                        match uid_opt {
                            None => {
                                audit.record(ProxyEvent::RejectedUidUnknown {
                                    config_id: cfg.id.clone(),
                                });
                                drop(stream);
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
                                let cfg_inner = Arc::clone(&cfg);
                                let cc_inner = Arc::clone(&client_config);
                                let audit_inner = Arc::clone(&audit);
                                tokio::spawn(async move {
                                    if let Err(e) = bridge_to_mtls_upstream(stream, cc_inner, &cfg_inner).await {
                                        audit_inner.record(ProxyEvent::BridgeFailed {
                                            config_id: cfg_inner.id.clone(),
                                            reason: e.to_string(),
                                        });
                                    }
                                });
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
}
