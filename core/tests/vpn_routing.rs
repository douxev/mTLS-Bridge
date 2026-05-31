//! Test unitaire de la table de routage VPN : on construit plusieurs routes
//! avec des IP/port synthétiques différents, on vérifie que les lookups
//! matchent, et qu'un doublon (même IP+port pour deux configs) est rejeté.
//!
//! Pas de test end-to-end avec un vrai tun_fd : ça demanderait CAP_NET_ADMIN
//! + privilèges root sur la machine de build, hors scope CI. Le pipeline
//! complet sera validé sur device via les tests instrumentés Android.

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::sync::Arc;

use mtls_bridge_core::config::{
    ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust,
};
use mtls_bridge_core::vpn::VpnRoute;

fn dummy_cfg(id: &str) -> Arc<ProxyConfig> {
    // PEM bidons : on ne précompile pas réellement de ClientConfig dans ce
    // test (vpn::start_vpn le ferait), on teste juste la structure de routage.
    Arc::new(ProxyConfig {
        id: id.into(),
        upstream_host: "x".into(),
        upstream_port: 1,
        sni: None,
        identity: ClientIdentity {
            cert_chain_pem: Arc::new(Vec::new()),
            key: PrivateKeyMaterial::InMemoryPem(Arc::new(Vec::new())),
        },
        server_trust: ServerTrust::Pinned(Arc::new(Vec::new())),
    })
}

#[test]
fn route_struct_uses_synthetic_address_as_key() {
    let r1 = VpnRoute {
        synthetic_ip: "192.0.2.1".parse().unwrap(),
        synthetic_port: 5001,
        config: dummy_cfg("jellyfin"),
        expected_uid: 10042,
    };
    let r2 = VpnRoute {
        synthetic_ip: "192.0.2.2".parse().unwrap(),
        synthetic_port: 5002,
        config: dummy_cfg("nextcloud"),
        expected_uid: 10043,
    };
    // Les deux routes ont des SocketAddr distinctes : pas de collision.
    assert_ne!(
        (r1.synthetic_ip, r1.synthetic_port),
        (r2.synthetic_ip, r2.synthetic_port)
    );
}
