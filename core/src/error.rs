use std::io;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("invalid config: {0}")]
    Config(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("invalid pkcs#8 / pem: {0}")]
    Pem(String),
    #[error("peer UID {peer} != expected UID {expected} for this config")]
    PeerUidMismatch { peer: u32, expected: u32 },
    #[error("proxy already running")]
    AlreadyRunning,
    #[error("internal: {0}")]
    Internal(String),
}

impl From<io::Error> for CoreError {
    fn from(e: io::Error) -> Self {
        CoreError::Io(e.to_string())
    }
}

impl From<rustls::Error> for CoreError {
    fn from(e: rustls::Error) -> Self {
        CoreError::Tls(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
