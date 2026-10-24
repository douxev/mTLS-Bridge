//! Runtime tokio dédié aux proxys.
//!
//! Les fonctions async exportées par uniffi (`async_runtime = "tokio"`)
//! tournent sous async-compat, dont le runtime global est un current_thread
//! piloté par un seul thread : tout `tokio::spawn` fait depuis ces fonctions
//! y atterrit. Les callbacks Kotlin synchrones — signature Keystore pendant
//! le handshake mTLS (jusqu'à ~1 s sur StrongBox), `getConnectionOwnerUid` à
//! chaque accept — bloquaient alors toutes les connexions de tous les
//! proxys.
//!
//! Les entrées FFI démarrent donc les proxys sur un runtime multi-thread à 2
//! workers ([`run`]) : listeners, netstack VPN et sessions y vivent. Les
//! appels bloquants passent par [`blocking`], qui libère le worker pendant
//! l'appel : un handshake qui signe n'immobilise plus les autres sessions.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};

use crate::error::{CoreError, Result};

/// Deux workers : du forwarding n'a pas besoin de plus, et chaque worker
/// réveillé coûte de la batterie.
const WORKERS: usize = 2;

fn runtime() -> Result<&'static Runtime> {
    static RUNTIME: OnceLock<std::io::Result<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread()
                .worker_threads(WORKERS)
                .thread_name("mtls-proxy")
                .enable_all()
                .build()
        })
        .as_ref()
        .map_err(|e| CoreError::Internal(format!("runtime proxy: {e}")))
}

/// Exécute `fut` sur le runtime des proxys et attend son résultat, depuis
/// n'importe quel contexte (runtime d'async-compat compris). Les tâches que
/// `fut` spawn, et les sockets qu'il ouvre, appartiennent à ce runtime.
pub(crate) async fn run<F>(fut: F) -> Result<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    runtime()?
        .spawn(fut)
        .await
        .map_err(|e| CoreError::Internal(format!("tâche proxy interrompue: {e}")))
}

/// Appel synchrone potentiellement long (callback Kotlin). Sur un worker du
/// runtime multi-thread, `block_in_place` confie les autres tâches du worker
/// à un autre thread le temps de l'appel. Ailleurs (runtime current_thread
/// des tests ou d'async-compat, où `block_in_place` paniquerait — et
/// panic=abort tue l'app), l'appel est fait tel quel.
pub(crate) fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_runs_outside_any_runtime() {
        assert_eq!(blocking(|| 7), 7);
    }

    #[tokio::test]
    async fn blocking_does_not_panic_on_current_thread_runtime() {
        assert_eq!(blocking(|| 7), 7);
    }

    #[tokio::test]
    async fn run_executes_on_the_dedicated_multi_thread_runtime() {
        let flavor = run(async { Handle::current().runtime_flavor() })
            .await
            .unwrap();
        assert_eq!(flavor, RuntimeFlavor::MultiThread);
        let name = run(async { std::thread::current().name().map(str::to_string) })
            .await
            .unwrap();
        assert_eq!(name.as_deref(), Some("mtls-proxy"));
        // Sur un worker, block_in_place est utilisé (pas de panique).
        assert_eq!(run(async { blocking(|| 7) }).await.unwrap(), 7);
    }
}
