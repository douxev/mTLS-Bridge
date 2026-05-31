use std::sync::Arc;

use crate::signer::KeystoreSigner;

/// Configuration d'un proxy mTLS pour une app cliente.
///
/// L'identité cliente (chaîne de certs + clé privée) est encapsulée par
/// [`ClientIdentity`] qui peut être soit chargée en RAM (tests) soit déléguée
/// à un [`KeystoreSigner`] côté Android (production).
#[derive(Clone)]
pub struct ProxyConfig {
    /// Identifiant logique de la config (UI). Doit être stable.
    pub id: String,
    /// Hôte distant (DNS ou IP).
    pub upstream_host: String,
    /// Port distant.
    pub upstream_port: u16,
    /// SNI à envoyer dans le handshake TLS. Défaut = `upstream_host`.
    pub sni: Option<String>,
    /// Identité client + politique de validation serveur.
    pub identity: ClientIdentity,
    /// CA distante à épingler. `None` = trust store système (déconseillé en prod).
    pub server_trust: ServerTrust,
}

#[derive(Clone)]
pub enum ServerTrust {
    /// Épingle un ou plusieurs certificats CA (PEM, concaténés).
    Pinned(Arc<Vec<u8>>),
    /// Trust store du système (peu utile sur Android sans intégration plate-forme).
    SystemRoots,
}

#[derive(Clone)]
pub struct ClientIdentity {
    /// Chaîne de certificats du client (PEM, leaf en premier).
    pub cert_chain_pem: Arc<Vec<u8>>,
    /// Clé privée — soit en RAM (test/MVP), soit handle vers Keystore (phase C).
    pub key: PrivateKeyMaterial,
}

#[derive(Clone)]
pub enum PrivateKeyMaterial {
    /// Clé en clair, en RAM. **À ne pas utiliser sur device** : la RAM Android
    /// est balayable depuis le debugger ADB et la clé doit rester dans le TEE.
    /// Acceptable pour tests d'intégration et migration depuis un .p12.
    InMemoryPem(Arc<Vec<u8>>),
    /// Délégation vers Android Keystore via un callback uniffi. Le `handle`
    /// est l'alias Keystore (identifiant opaque côté Rust). Le `signer` est
    /// fourni par l'hôte Android (implémente [`KeystoreSigner`] côté Kotlin).
    Keystore {
        handle: String,
        signer: Arc<dyn KeystoreSigner>,
    },
}
