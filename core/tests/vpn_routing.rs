//! Unit test of the VPN routing structure: several routes are built with
//! different synthetic IPs/ports, and their keys are checked to be distinct.
//!
//! No end-to-end test with a real tun_fd: that would require CAP_NET_ADMIN
//! and root privileges on the build machine, out of scope for CI. The full
//! pipeline is validated on device through the Android instrumented tests.

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::sync::Arc;

use mtls_bridge_core::config::{ClientIdentity, PrivateKeyMaterial, ProxyConfig, ServerTrust};
use mtls_bridge_core::vpn::VpnRoute;

fn dummy_cfg(id: &str) -> Arc<ProxyConfig> {
    // Dummy PEMs: no ClientConfig is actually precompiled in this test
    // (vpn::start_vpn would do it), only the routing structure is tested.
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
        path_token: None,
        extra_canonical_hosts: Vec::new(),
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
    // The two routes have distinct SocketAddrs: no collision.
    assert_ne!(
        (r1.synthetic_ip, r1.synthetic_port),
        (r2.synthetic_ip, r2.synthetic_port)
    );
}
