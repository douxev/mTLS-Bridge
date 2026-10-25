//! Bridge between rustls and the Android Keystore.
//!
//! The private key lives in the Android TEE (hardware-backed Keystore). During
//! the mTLS handshake, rustls needs to sign a message (CertificateVerify).
//! The key cannot be handed to it: instead it gets an object implementing
//! [`rustls::sign::SigningKey`] that delegates to a Rust trait ([`KeystoreSigner`])
//! exported to Kotlin through uniffi. On the Kotlin side, the implementation
//! calls `KeyStore.getKey(alias)` + `Signature.getInstance(...)`, which runs
//! the signature in the TEE: the key never leaves the hardware.

use std::fmt;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
/// TLS signature schemes supported by Android Keystore.
///
/// They are exported to uniffi through our own enum instead of
/// `rustls::SignatureScheme` (which uniffi cannot derive). The one-to-one
/// mapping to/from rustls is in [`scheme_to_rustls`] / [`scheme_from_rustls`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, uniffi::Enum)]
pub enum TlsSignatureScheme {
    EcdsaNistp256Sha256,
    EcdsaNistp384Sha384,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SignerError {
    #[error("signature scheme not supported by this key")]
    Unsupported,
    #[error("key not found or unusable")]
    KeyUnavailable,
    #[error("signature: {0}")]
    Failed(String),
}

/// Trait implemented on the Kotlin side (uniffi callback). One instance per
/// device (often a singleton that talks to the Android `KeyStore`).
#[uniffi::export(with_foreign)]
pub trait KeystoreSigner: Send + Sync {
    /// Signs `data` with the key identified by `key_handle` using `scheme`.
    /// The Kotlin implementation must use `Signature.getInstance` with the
    /// matching algorithm and go through the Keystore `PrivateKey`.
    fn sign(
        &self,
        key_handle: String,
        scheme: TlsSignatureScheme,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SignerError>;

    /// Schemes that the key `key_handle` can produce. On the Kotlin side this
    /// is determined by `KeyInfo.getKeyAlgorithm()` + key size/curve.
    fn supported_schemes(&self, key_handle: String) -> Vec<TlsSignatureScheme>;
}

pub fn scheme_to_rustls(s: TlsSignatureScheme) -> SignatureScheme {
    match s {
        TlsSignatureScheme::EcdsaNistp256Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        TlsSignatureScheme::EcdsaNistp384Sha384 => SignatureScheme::ECDSA_NISTP384_SHA384,
        TlsSignatureScheme::RsaPssSha256 => SignatureScheme::RSA_PSS_SHA256,
        TlsSignatureScheme::RsaPssSha384 => SignatureScheme::RSA_PSS_SHA384,
        TlsSignatureScheme::RsaPssSha512 => SignatureScheme::RSA_PSS_SHA512,
        TlsSignatureScheme::RsaPkcs1Sha256 => SignatureScheme::RSA_PKCS1_SHA256,
        TlsSignatureScheme::RsaPkcs1Sha384 => SignatureScheme::RSA_PKCS1_SHA384,
        TlsSignatureScheme::RsaPkcs1Sha512 => SignatureScheme::RSA_PKCS1_SHA512,
    }
}

pub fn scheme_from_rustls(s: SignatureScheme) -> Option<TlsSignatureScheme> {
    match s {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Some(TlsSignatureScheme::EcdsaNistp256Sha256),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Some(TlsSignatureScheme::EcdsaNistp384Sha384),
        SignatureScheme::RSA_PSS_SHA256 => Some(TlsSignatureScheme::RsaPssSha256),
        SignatureScheme::RSA_PSS_SHA384 => Some(TlsSignatureScheme::RsaPssSha384),
        SignatureScheme::RSA_PSS_SHA512 => Some(TlsSignatureScheme::RsaPssSha512),
        SignatureScheme::RSA_PKCS1_SHA256 => Some(TlsSignatureScheme::RsaPkcs1Sha256),
        SignatureScheme::RSA_PKCS1_SHA384 => Some(TlsSignatureScheme::RsaPkcs1Sha384),
        SignatureScheme::RSA_PKCS1_SHA512 => Some(TlsSignatureScheme::RsaPkcs1Sha512),
        _ => None,
    }
}

/// rustls `SigningKey` that delegates signing to the Keystore callback.
pub(crate) struct CallbackSigningKey {
    pub handle: String,
    pub callback: Arc<dyn KeystoreSigner>,
    pub supported: Vec<SignatureScheme>,
    pub algorithm: SignatureAlgorithm,
}

impl fmt::Debug for CallbackSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackSigningKey")
            .field("handle", &self.handle)
            .field("supported", &self.supported)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl SigningKey for CallbackSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Pick the first scheme offered by the server that is supported:
        // the server's order reflects its preference (RFC 8446 §4.2.3).
        for o in offered {
            if self.supported.contains(o) {
                return Some(Box::new(CallbackSigner {
                    scheme: *o,
                    handle: self.handle.clone(),
                    callback: Arc::clone(&self.callback),
                }));
            }
        }
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

pub(crate) struct CallbackSigner {
    scheme: SignatureScheme,
    handle: String,
    callback: Arc<dyn KeystoreSigner>,
}

impl fmt::Debug for CallbackSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallbackSigner")
            .field("handle", &self.handle)
            .field("scheme", &self.scheme)
            .finish()
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let our_scheme = scheme_from_rustls(self.scheme).ok_or_else(|| {
            rustls::Error::General(format!("scheme {:?} cannot be mapped", self.scheme))
        })?;
        // Blocking Kotlin call (TEE/StrongBox) in the middle of the handshake:
        // the worker is freed for the other sessions in the meantime.
        crate::runtime::blocking(|| {
            self.callback
                .sign(self.handle.clone(), our_scheme, message.to_vec())
        })
        .map_err(|e| rustls::Error::General(format!("keystore: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Resolver that always returns the same `CertifiedKey` (a single client cert
/// per connection, which is the case here). The server may send a list of
/// acceptable CAs through `root_hint_subjects`; it is ignored: the user has
/// explicitly configured the cert to use for this upstream.
#[derive(Debug)]
pub(crate) struct CallbackResolvesClientCert {
    pub certified: Arc<CertifiedKey>,
}

impl ResolvesClientCert for CallbackResolvesClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified))
    }

    fn has_certs(&self) -> bool {
        true
    }
}
