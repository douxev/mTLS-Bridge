//! Mode VPN : on reçoit un `tun_fd` depuis le `VpnService` Android et on
//! parse les paquets IP avec netstack-smoltcp pour reconstruire des sessions
//! TCP utilisables comme des `AsyncRead+AsyncWrite`. Le routage se fait par
//! couple `(IP_synthetique, port)` : la doxev configure son app cible avec
//! `http://192.0.2.X:port` (TEST-NET, RFC 5737), et on mappe cette adresse
//! vers la `ProxyConfig` correspondante.
//!
//! Sécurité : aucun UID check explicite n'est nécessaire dans ce mode parce
//! que `VpnService.Builder.addAllowedApplication(pkg)` filtre les paquets au
//! niveau du noyau Android avant qu'ils n'arrivent dans notre tun.

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures::{Sink, SinkExt, Stream, StreamExt};
use netstack_smoltcp::{AnyIpPktFrame, StackBuilder};
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::config::ProxyConfig;
use crate::error::{CoreError, Result};
use crate::loopback::{AuditLogger, PeerUidResolver, ProxyEvent};
use crate::proxy::{bridge_to_mtls_upstream, precompile_client_config, stop_requested};

/// Une route VPN : une adresse synthétique → la config mTLS associée.
#[derive(Clone)]
pub struct VpnRoute {
    pub synthetic_ip: IpAddr,
    pub synthetic_port: u16,
    pub config: Arc<ProxyConfig>,
    /// UID Android attendu pour cette config (uid de targetPackage). On vérifie
    /// que chaque connexion accepte par ce tun appartient bien à cet UID — en
    /// plus de addAllowedApplication côté Kotlin qui filtre déjà au niveau
    /// noyau. Défense en profondeur contre une appli autorisée qui essaierait
    /// de viser l'IP synthétique d'une AUTRE app dans le même tun.
    pub expected_uid: u32,
}

impl VpnRoute {
    fn key(&self) -> SocketAddr {
        SocketAddr::new(self.synthetic_ip, self.synthetic_port)
    }
}

struct RouteEntry {
    cfg: Arc<ProxyConfig>,
    client_config: Arc<rustls::ClientConfig>,
    expected_uid: u32,
}

/// Table de routage : (IP_synth, port) → route complète.
struct RoutingTable {
    table: HashMap<SocketAddr, RouteEntry>,
}

impl RoutingTable {
    fn from_routes(routes: Vec<VpnRoute>) -> Result<Self> {
        let mut table = HashMap::new();
        for r in routes {
            let key = r.key();
            let client_config = precompile_client_config(&r.config)?;
            if table
                .insert(
                    key,
                    RouteEntry {
                        cfg: r.config,
                        client_config,
                        expected_uid: r.expected_uid,
                    },
                )
                .is_some()
            {
                return Err(CoreError::Config(format!(
                    "deux routes pointent sur la même IP synthétique {key}"
                )));
            }
        }
        Ok(Self { table })
    }

    fn lookup(&self, dest: SocketAddr) -> Option<&RouteEntry> {
        self.table.get(&dest)
    }
}

// ---------------------------------------------------------------------------
// Adapter Stream/Sink autour d'un tun_fd brut (typiquement transmis par
// l'Android VpnService via ParcelFileDescriptor.detachFd()).
// ---------------------------------------------------------------------------

pub struct TunFd {
    fd: AsyncFd<OwnedFd>,
    mtu: usize,
    write_buf: Option<Vec<u8>>,
}

impl TunFd {
    /// Adopte un fd brut. Le fd sera fermé quand `TunFd` est drop.
    /// Le fd **doit** être en mode non-bloquant — sur Android, le fd renvoyé
    /// par `VpnService.Builder.establish()` ne l'est pas par défaut, donc
    /// on force `O_NONBLOCK` ici.
    pub fn from_raw_fd(raw: RawFd, mtu: usize) -> Result<Self> {
        if raw < 0 {
            return Err(CoreError::Config(format!("tun_fd invalide ({raw})")));
        }
        // SAFETY : l'appelant garantit l'unique propriété du fd (typiquement
        // après ParcelFileDescriptor.detachFd() côté Kotlin).
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        set_nonblocking(owned.as_raw_fd())?;
        Ok(Self {
            fd: AsyncFd::new(owned).map_err(|e| CoreError::Io(e.to_string()))?,
            mtu,
            write_buf: None,
        })
    }
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY : appels libc directs sur un fd valide.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(CoreError::Io(std::io::Error::last_os_error().to_string()));
    }
    let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if r < 0 {
        return Err(CoreError::Io(std::io::Error::last_os_error().to_string()));
    }
    Ok(())
}

impl Stream for TunFd {
    type Item = std::io::Result<AnyIpPktFrame>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            let mut guard = match ready!(this.fd.poll_read_ready_mut(cx)) {
                Ok(g) => g,
                Err(e) => return Poll::Ready(Some(Err(e))),
            };
            let mut buf = vec![0u8; this.mtu];
            let res = guard.try_io(|inner| {
                // SAFETY : buf valide pour mtu octets, fd valide géré par AsyncFd.
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    return Poll::Ready(Some(Ok(buf)));
                }
                Ok(Err(e)) => return Poll::Ready(Some(Err(e))),
                Err(_would_block) => continue,
            }
        }
    }
}

impl Sink<AnyIpPktFrame> for TunFd {
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        // Si on a un buffer pending, on doit d'abord le drainer.
        if self.write_buf.is_some() {
            self.poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(
        self: Pin<&mut Self>,
        item: AnyIpPktFrame,
    ) -> std::result::Result<(), Self::Error> {
        let this = self.get_mut();
        debug_assert!(
            this.write_buf.is_none(),
            "start_send sans poll_ready préalable"
        );
        this.write_buf = Some(item);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        let this = self.get_mut();
        loop {
            let Some(buf) = this.write_buf.as_ref() else {
                return Poll::Ready(Ok(()));
            };
            let mut guard = ready!(this.fd.poll_write_ready_mut(cx))?;
            let res = guard.try_io(|inner| {
                // SAFETY : buf valide, fd valide géré par AsyncFd.
                let n = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buf.as_ptr() as *const _,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match res {
                Ok(Ok(_n)) => {
                    // Pour un tun device, write atomique : on envoie le paquet
                    // entier en un syscall ou on échoue. Pas de partial-write.
                    this.write_buf = None;
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => {
                    this.write_buf = None;
                    return Poll::Ready(Err(e));
                }
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}

// ---------------------------------------------------------------------------
// Public API : start_vpn(tun_fd, mtu, routes, audit) -> Arc<VpnHandle>
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct VpnHandle {
    stop_tx: watch::Sender<bool>,
    tasks: std::sync::Mutex<Vec<JoinHandle<()>>>,
}

#[uniffi::export]
impl VpnHandle {
    /// Demande l'arrêt : le pont tun ↔ netstack s'interrompt (le tun_fd est
    /// fermé) et toutes les sessions en cours sont fermées.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(true);
    }
}

impl Drop for VpnHandle {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(true);
        if let Ok(mut ts) = self.tasks.lock() {
            for t in ts.drain(..) {
                t.abort();
            }
        }
    }
}

pub async fn start_vpn(
    tun_fd: i32,
    mtu: u32,
    routes: Vec<VpnRoute>,
    uid_resolver: Arc<dyn PeerUidResolver>,
    audit: Arc<dyn AuditLogger>,
) -> Result<Arc<VpnHandle>> {
    crate::init_crypto_provider();
    // Adopter le fd AVANT toute étape faillible : resté brut, personne ne le
    // fermerait si une route est invalide ou si netstack échoue, et
    // l'interface VPN resterait montée.
    let tun = TunFd::from_raw_fd(tun_fd as RawFd, mtu as usize)?;
    let routing = Arc::new(RoutingTable::from_routes(routes)?);

    let (stack, tcp_runner, _udp, tcp_listener) = StackBuilder::default()
        .stack_buffer_size(512)
        .tcp_buffer_size(4096)
        .enable_tcp(true)
        .enable_icmp(true)
        .mtu(mtu as usize)
        .build()
        .map_err(|e| CoreError::Internal(format!("netstack build: {e}")))?;
    let tcp_listener = tcp_listener
        .ok_or_else(|| CoreError::Internal("tcp listener absent (tcp non activé ?)".into()))?;

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    // 1) Tâche runner du netstack (poll smoltcp interface).
    if let Some(runner) = tcp_runner {
        let mut stop_for_runner = stop_rx.clone();
        tasks.push(tokio::spawn(async move {
            tokio::select! {
                () = stop_requested(&mut stop_for_runner) => {}
                res = runner => match res {
                    Ok(()) => log::warn!("netstack tcp_runner s'est terminé proprement"),
                    Err(e) => log::error!("netstack tcp_runner a échoué: {e}"),
                },
            }
        }));
    } else {
        log::error!("pas de tcp_runner — TCP désactivé dans StackBuilder ?");
    }

    // 2) Pont bidi tun ↔ stack.
    let (stack_sink, stack_stream) = stack.split();
    let (tun_sink, tun_stream) = tun.split();
    let mut stop_for_tun_to_stack = stop_rx.clone();
    let mut tun_stream = tun_stream;
    let mut stack_sink = stack_sink;
    tasks.push(tokio::spawn(async move {
        let mut counter: u64 = 0;
        loop {
            tokio::select! {
                biased;
                _ = stop_for_tun_to_stack.changed() => {
                    if *stop_for_tun_to_stack.borrow() { break; }
                }
                pkt = tun_stream.next() => {
                    match pkt {
                        Some(Ok(p)) => {
                            counter += 1;
                            if counter <= 20 || counter % 100 == 0 {
                                log::info!("tun→stack #{counter} len={}", p.len());
                            }
                            if let Err(e) = stack_sink.send(p).await {
                                log::error!("stack_sink.send failed: {e}");
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            log::error!("tun read error: {e}");
                            break;
                        }
                        None => {
                            log::info!("tun stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }));

    let mut stop_for_stack_to_tun = stop_rx.clone();
    let mut stack_stream = stack_stream;
    let mut tun_sink = tun_sink;
    tasks.push(tokio::spawn(async move {
        let mut counter: u64 = 0;
        loop {
            tokio::select! {
                biased;
                _ = stop_for_stack_to_tun.changed() => {
                    if *stop_for_stack_to_tun.borrow() { break; }
                }
                pkt = stack_stream.next() => {
                    match pkt {
                        Some(Ok(p)) => {
                            counter += 1;
                            if counter <= 20 || counter % 100 == 0 {
                                log::info!("stack→tun #{counter} len={}", p.len());
                            }
                            if let Err(e) = tun_sink.send(p).await {
                                log::error!("tun_sink.send failed: {e}");
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            log::error!("stack_stream error: {e}");
                            break;
                        }
                        None => {
                            log::info!("stack_stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }));

    // 3) Accept loop : pour chaque TCP virtuel, lookup dans la routing table
    //    puis bridge mTLS.
    let mut stop_for_accept = stop_rx;
    let routing_for_accept = Arc::clone(&routing);
    let audit_for_accept = Arc::clone(&audit);
    let uid_resolver_for_accept = Arc::clone(&uid_resolver);
    tasks.push(tokio::spawn(async move {
        let mut listener = tcp_listener;
        // Sessions en cours : abortées ensemble à l'arrêt.
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = stop_requested(&mut stop_for_accept) => break,
                // Récolte des sessions terminées, sinon le JoinSet grossit.
                Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
                next = listener.next() => {
                    // ATTENTION sémantique netstack-smoltcp inversée :
                    // - local_addr  = src_addr (= l'app cliente, IP du tun + port éphémère)
                    // - remote_addr = dst_addr (= NOTRE IP synthétique, clé de routage)
                    let Some((stream, src_addr, dst_addr)) = next else { break; };
                    let Some(route) = routing_for_accept.lookup(dst_addr) else {
                        audit_for_accept.record(ProxyEvent::VpnRouteMissing {
                            synthetic_ip: dst_addr.ip().to_string(),
                            synthetic_port: dst_addr.port(),
                        });
                        continue;
                    };
                    let cfg = Arc::clone(&route.cfg);
                    let cc = Arc::clone(&route.client_config);
                    let expected_uid = route.expected_uid;

                    // Défense en profondeur : addAllowedApplication filtre déjà
                    // les paquets au niveau noyau (une app non autorisée NE
                    // PEUT PAS arriver ici). Mais SI deux apps sont allow-listed
                    // et que l'une vise l'IP synthétique de l'autre, on doit
                    // refuser : sinon elle obtiendrait le cert mTLS de l'autre.
                    //
                    // Convention "depuis le pair" : son local = src_addr (son
                    // ephémère dans le tun), son remote = dst_addr (notre IP
                    // synthétique). Si l'API Android ne sait pas lire les
                    // sockets VPN-routés (= renvoie None), on **soft-fail** :
                    // on log un avertissement et on accepte, parce que la
                    // garantie addAllowedApplication reste tenue par l'OS.
                    let uid_opt = crate::runtime::blocking(|| {
                        uid_resolver_for_accept.peer_uid(
                            src_addr.ip().to_string(),
                            src_addr.port(),
                            dst_addr.ip().to_string(),
                            dst_addr.port(),
                        )
                    });
                    match uid_opt {
                        Some(uid) if uid != expected_uid => {
                            audit_for_accept.record(ProxyEvent::RejectedUidMismatch {
                                config_id: cfg.id.clone(),
                                peer_uid: uid,
                                expected_uid,
                            });
                            drop(stream);
                            continue;
                        }
                        Some(_) => {} // OK, UID match
                        None => {
                            // L'API ne supporte pas les sockets VPN sur ce
                            // device — on continue en mode "OS-enforced only".
                            log::debug!(
                                "VPN UID lookup unsupported pour {src_addr}↔{dst_addr}, \
                                 fallback addAllowedApplication"
                            );
                        }
                    }
                    audit_for_accept.record(ProxyEvent::VpnRouteHit {
                        config_id: cfg.id.clone(),
                        synthetic_ip: dst_addr.ip().to_string(),
                        synthetic_port: dst_addr.port(),
                    });
                    let cfg_inner = Arc::clone(&cfg);
                    let audit_inner = Arc::clone(&audit_for_accept);
                    sessions.spawn(async move {
                        // Mode VPN : pas de réécriture de réponse — la cible voit
                        // déjà directement l'IP synthétique, pas d'URL loopback
                        // canonique vers laquelle réécrire les URLs upstream.
                        if let Err(e) = bridge_to_mtls_upstream(stream, cc, &cfg_inner, None).await {
                            audit_inner.record(ProxyEvent::BridgeFailed {
                                config_id: cfg_inner.id.clone(),
                                reason: e.to_string(),
                            });
                        }
                    });
                }
            }
        }
        sessions.shutdown().await;
    }));

    audit.record(ProxyEvent::VpnStarted {
        route_count: routing.table.len() as u32,
    });
    Ok(Arc::new(VpnHandle {
        stop_tx,
        tasks: std::sync::Mutex::new(tasks),
    }))
}
