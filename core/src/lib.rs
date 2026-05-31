uniffi::setup_scaffolding!();

pub mod config;
pub mod error;
pub mod ffi_api;
pub mod http_rewrite;
pub mod loopback;
pub mod proxy;
pub mod signer;
pub mod tls;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod vpn;

use std::sync::Once;

/// Installe `aws-lc-rs` comme provider crypto par défaut pour rustls.
/// Idempotent : appelable en boucle, n'installe qu'au premier appel.
///
/// rustls 0.23 exige un provider installé explicitement avant tout build de
/// `ClientConfig` / `ServerConfig`. Sinon : panic "no process-level
/// CryptoProvider available" au premier handshake.
pub fn init_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Configure le logger Rust. Sur Android, route vers `adb logcat` (tag
/// `mtls_bridge.rust`). Sur host (tests), route vers stderr via env_logger
/// si dispo (sinon no-op). Idempotent.
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
    format!("Bonjour {name}, depuis le cœur Rust de mTLS Bridge")
}

#[uniffi::export]
fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
