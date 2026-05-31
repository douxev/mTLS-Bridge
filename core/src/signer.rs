//! Pont entre rustls et le Keystore Android.
//!
//! La clé privée vit dans le TEE Android (Keystore hardware-backed). Pendant le
//! handshake mTLS, rustls a besoin de signer un message (CertificateVerify).
//! On ne peut pas lui donner la clé : on lui donne un objet implémentant
//! [`rustls::sign::SigningKey`] qui délègue à un trait Rust ([`KeystoreSigner`])
//! exposé via uniffi à Kotlin. Côté Kotlin, l'implémentation appelle
//! `KeyStore.getKey(alias)` + `Signature.getInstance(...)` qui exécute la
//! signature dans le TEE — la clé ne quitte jamais le matériel.

use std::fmt;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
/// Schémas de signature TLS supportés par Android Keystore.
///
/// On les expose à uniffi avec une enum propre à nous au lieu d'utiliser
/// `rustls::SignatureScheme` (que uniffi ne peut pas dériver). Le mapping
/// 1-pour-1 vers/depuis rustls est dans [`scheme_to_rustls`] / [`scheme_from_rustls`].
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
    #[error("schéma de signature non supporté par cette clé")]
    Unsupported,
    #[error("clé introuvable ou inutilisable")]
    KeyUnavailable,
    #[error("signature: {0}")]
    Failed(String),
}

/// Trait implémenté côté Kotlin (callback uniffi). Une instance par device
/// (souvent un singleton qui parle au `KeyStore` Android).
#[uniffi::export(with_foreign)]
pub trait KeystoreSigner: Send + Sync {
    /// Signe `data` avec la clé identifiée par `key_handle` selon `scheme`.
    /// L'implémentation Kotlin doit utiliser `Signature.getInstance` avec
    /// l'algo correspondant et passer par le `PrivateKey` Keystore.
    fn sign(
        &self,
        key_handle: String,
        scheme: TlsSignatureScheme,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, SignerError>;

    /// Liste des schémas que la clé `key_handle` peut produire. Côté Kotlin
    /// déterminé par `KeyInfo.getKeyAlgorithm()` + taille/courbe.
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

/// `SigningKey` rustls qui délègue la signature au callback Keystore.
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
        // On prend le premier schéma proposé par le serveur qu'on supporte —
        // l'ordre du serveur reflète sa préférence (RFC 8446 §4.2.3).
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
            rustls::Error::General(format!("scheme {:?} non mappable", self.scheme))
        })?;
        self.callback
            .sign(self.handle.clone(), our_scheme, message.to_vec())
            .map_err(|e| rustls::Error::General(format!("keystore: {e}")))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// Resolver qui renvoie toujours la même `CertifiedKey` (un seul cert client
/// par connexion, c'est notre cas). Le serveur peut envoyer une liste de CA
/// acceptables via `root_hint_subjects` — on l'ignore : le user a configuré
/// explicitement le cert à utiliser pour cet upstream.
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
