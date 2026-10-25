//! Wrappers exported through uniffi to drive both modes from Kotlin.
//!
//! The internal types (`ProxyConfig`, `Arc<dyn KeystoreSigner>`) are not
//! `uniffi::Record`-compatible; they are built here from flat structs passed
//! in by the Android host.

use std::sync::Arc;

use crate::config::{ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust};
use crate::error::Result;
use crate::loopback::{start_loopback, AuditLogger, LoopbackHandle, PeerUidResolver};
use crate::signer::KeystoreSigner;

#[derive(Clone, uniffi::Record)]
pub struct ProxyConfigSpec {
    pub id: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub sni: Option<String>,
    pub cert_chain_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
    pub keystore_alias: String,
    /// Loopback only. URL-safe token inserted in the HTTP path.
    pub path_token: Option<String>,
    /// Additional canonical hosts (without scheme) to rewrite to the
    /// loopback address. See [`ProxyConfig::extra_canonical_hosts`].
    pub extra_canonical_hosts: Vec<String>,
}

fn build_proxy_config(spec: ProxyConfigSpec, signer: Arc<dyn KeystoreSigner>) -> Arc<ProxyConfig> {
    Arc::new(ProxyConfig {
        id: spec.id,
        upstream_host: spec.upstream_host,
        upstream_port: spec.upstream_port,
        sni: spec.sni,
        identity: ClientIdentity {
            cert_chain_pem: Arc::new(spec.cert_chain_pem),
            key: PrivateKeyMaterial::Keystore {
                handle: spec.keystore_alias,
                signer,
            },
        },
        server_trust: ServerTrust::Pinned(Arc::new(spec.ca_pem)),
        path_token: spec.path_token,
        extra_canonical_hosts: spec.extra_canonical_hosts,
    })
}

#[uniffi::export(async_runtime = "tokio")]
pub async fn start_loopback_proxy(
    config: ProxyConfigSpec,
    bind_port: u16,
    expected_uid: u32,
    signer: Arc<dyn KeystoreSigner>,
    uid_resolver: Arc<dyn PeerUidResolver>,
    audit: Arc<dyn AuditLogger>,
) -> Result<Arc<LoopbackHandle>> {
    let cfg = build_proxy_config(config, signer);
    // On the multi-threaded proxy runtime, not on the (single-threaded)
    // async-compat one: see crate::runtime.
    crate::runtime::run(start_loopback(
        cfg,
        bind_port,
        expected_uid,
        uid_resolver,
        audit,
    ))
    .await?
}

// ----- VPN -----

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, uniffi::Record)]
pub struct VpnRouteSpec {
    pub synthetic_ip: String,
    pub synthetic_port: u16,
    /// Android UID of the target app (PackageManager.getApplicationInfo(pkg).uid).
    /// Checked on every accept on the Rust side as defense in depth, so that an
    /// authorized app cannot target the synthetic IP of another one.
    pub expected_uid: u32,
    pub config: ProxyConfigSpec,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[uniffi::export(async_runtime = "tokio")]
pub async fn start_vpn_proxy(
    tun_fd: i32,
    mtu: u32,
    routes: Vec<VpnRouteSpec>,
    signer: Arc<dyn KeystoreSigner>,
    uid_resolver: Arc<dyn PeerUidResolver>,
    audit: Arc<dyn AuditLogger>,
) -> Result<Arc<crate::vpn::VpnHandle>> {
    let parsed_routes = routes
        .into_iter()
        .map(|r| {
            let ip = r
                .synthetic_ip
                .parse()
                .map_err(|e| crate::error::CoreError::Config(format!("synthetic ip: {e}")))?;
            Ok::<_, crate::error::CoreError>(crate::vpn::VpnRoute {
                synthetic_ip: ip,
                synthetic_port: r.synthetic_port,
                config: build_proxy_config(r.config, Arc::clone(&signer)),
                expected_uid: r.expected_uid,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    crate::runtime::run(crate::vpn::start_vpn(
        tun_fd,
        mtu,
        parsed_routes,
        uid_resolver,
        audit,
    ))
    .await?
}
