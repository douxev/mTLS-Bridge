use std::io;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CoreError {
    #[error("io: {0}")]
    Io(String),
    #[error("config invalide: {0}")]
    Config(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("pkcs#8 / pem invalide: {0}")]
    Pem(String),
    #[error("UID du pair {peer} != UID attendu {expected} pour cette config")]
    PeerUidMismatch { peer: u32, expected: u32 },
    #[error("proxy déjà démarré")]
    AlreadyRunning,
    #[error("interne: {0}")]
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
