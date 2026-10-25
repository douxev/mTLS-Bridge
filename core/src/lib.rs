uniffi::setup_scaffolding!();

pub mod config;
pub mod error;
pub mod ffi_api;
pub mod http_rewrite;
pub mod loopback;
pub mod proxy;
mod runtime;
pub mod signer;
pub mod tls;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod vpn;

use std::sync::Once;

/// Installs `aws-lc-rs` as the default crypto provider for rustls.
/// Idempotent: can be called repeatedly, installs only on the first call.
///
/// rustls 0.23 requires a provider to be installed explicitly before any
/// `ClientConfig` / `ServerConfig` is built. Otherwise it panics with "no
/// process-level CryptoProvider available" on the first handshake.
pub fn init_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Configures the Rust logger. On Android, logs go to `adb logcat` (tag
/// `mtls_bridge.rust`). On the host (tests), logs go to stderr through
/// env_logger if available (no-op otherwise). Idempotent.
#[uniffi::export]
pub fn init_logging() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_tag("mtls_bridge.rust")
                    .with_max_level(log::LevelFilter::Debug),
            );
        }
    });
}

#[uniffi::export]
fn hello(name: String) -> String {
    format!("Hello {name}, from the mTLS Bridge Rust core")
}

#[uniffi::export]
fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
