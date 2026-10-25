//! Dedicated tokio runtime for the proxies.
//!
//! The async functions exported by uniffi (`async_runtime = "tokio"`) run
//! under async-compat, whose global runtime is a current_thread runtime
//! driven by a single thread: every `tokio::spawn` made from these functions
//! lands there. Synchronous Kotlin callbacks (Keystore signing during the
//! mTLS handshake, up to ~1 s on StrongBox; `getConnectionOwnerUid` on every
//! accept) used to block every connection of every proxy.
//!
//! The FFI entry points therefore start the proxies on a multi-threaded
//! runtime with 2 workers ([`run`]): listeners, the VPN netstack and the
//! sessions live there. Blocking calls go through [`blocking`], which frees
//! the worker during the call: a handshake that is signing no longer stalls
//! the other sessions.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Handle, Runtime, RuntimeFlavor};

use crate::error::{CoreError, Result};

/// Two workers: forwarding does not need more, and every worker that wakes
/// up costs battery.
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
        .map_err(|e| CoreError::Internal(format!("proxy runtime: {e}")))
}

/// Runs `fut` on the proxy runtime and waits for its result, from any
/// context (including the async-compat runtime). The tasks that `fut`
/// spawns, and the sockets it opens, belong to this runtime.
pub(crate) async fn run<F>(fut: F) -> Result<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    runtime()?
        .spawn(fut)
        .await
        .map_err(|e| CoreError::Internal(format!("proxy task interrupted: {e}")))
}

/// Potentially long synchronous call (Kotlin callback). On a worker of the
/// multi-threaded runtime, `block_in_place` hands the worker's other tasks
/// over to another thread for the duration of the call. Elsewhere (the
/// current_thread runtime of the tests or of async-compat, where
/// `block_in_place` would panic, and panic=abort kills the app), the call is
/// made as is.
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
        // On a worker, block_in_place is used (no panic).
        assert_eq!(run(async { blocking(|| 7) }).await.unwrap(), 7);
    }
}
