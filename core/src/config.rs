use std::sync::Arc;

use crate::signer::KeystoreSigner;

/// Configuration of an mTLS proxy for a client app.
///
/// The client identity (certificate chain + private key) is wrapped in
/// [`ClientIdentity`], which can either be loaded in RAM (tests) or delegated
/// to a [`KeystoreSigner`] on the Android side (production).
#[derive(Clone)]
pub struct ProxyConfig {
    /// Logical identifier of the config (UI). Must be stable.
    pub id: String,
    /// Remote host (DNS name or IP).
    pub upstream_host: String,
    /// Remote port.
    pub upstream_port: u16,
    /// SNI to send in the TLS handshake. Defaults to `upstream_host`.
    pub sni: Option<String>,
    /// Client identity + server validation policy.
    pub identity: ClientIdentity,
    /// Remote CA to pin. `None` = system trust store (not recommended in production).
    pub server_trust: ServerTrust,
    /// Optional: secret token in the first segment of the HTTP path. When
    /// set, the bridge only accepts requests whose URL starts with
    /// `/<token>/` (or `/<token>` for the root) or that carry the session
    /// cookie set in response to such a request (see
    /// [`crate::http_rewrite::PathAuth`]), strips that prefix before
    /// forwarding upstream, and closes fail-closed otherwise. Replaces UID
    /// isolation, which is not available to non-VPN apps on Android.
    pub path_token: Option<String>,
    /// Additional canonical hosts to rewrite to the loopback address in
    /// rewrite mode. Required when the backend application emits absolute
    /// URLs with a host different from the physical upstream (e.g. Nextcloud
    /// with an `overwrite.cli.url` that differs from the hostname used by the
    /// mTLS reverse proxy).
    pub extra_canonical_hosts: Vec<String>,
}

#[derive(Clone)]
pub enum ServerTrust {
    /// Pins one or more CA certificates (PEM, concatenated).
    Pinned(Arc<Vec<u8>>),
    /// System trust store (of little use on Android without platform integration).
    SystemRoots,
}

#[derive(Clone)]
pub struct ClientIdentity {
    /// Client certificate chain (PEM, leaf first).
    pub cert_chain_pem: Arc<Vec<u8>>,
    /// Private key: either in RAM (test/MVP) or a handle to the Keystore (phase C).
    pub key: PrivateKeyMaterial,
}

#[derive(Clone)]
pub enum PrivateKeyMaterial {
    /// Plaintext key in RAM. **Do not use on a device**: Android RAM can be
    /// scanned from the ADB debugger and the key must stay in the TEE.
    /// Acceptable for integration tests and for migrating from a .p12.
    InMemoryPem(Arc<Vec<u8>>),
    /// Delegation to Android Keystore through a uniffi callback. The `handle`
    /// is the Keystore alias (an opaque identifier on the Rust side). The
    /// `signer` is provided by the Android host (implements [`KeystoreSigner`]
    /// on the Kotlin side).
    Keystore {
        handle: String,
        signer: Arc<dyn KeystoreSigner>,
    },
}
