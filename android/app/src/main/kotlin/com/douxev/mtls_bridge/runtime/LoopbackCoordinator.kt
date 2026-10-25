package com.douxev.mtls_bridge.runtime

import android.content.Context
import com.douxev.mtls_bridge.data.AuditDao
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ConfigRepository
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.service.ProxyLauncher
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/**
 * Observes the config repo and keeps the [com.douxev.mtls_bridge.service.
 * LoopbackProxyService] service in sync with the list of `enabled` LOOPBACK
 * configs:
 *
 * - On each emission of the `observeAll()` flow, the delta between the
 *   current set and the previous one is computed.
 * - Added / enabled configs: `ProxyLauncher.startLoopback(...)`
 * - Deleted / disabled configs: `ProxyLauncher.stopLoopback(...)`
 *
 * Idempotent: starting an already running proxy is a no-op in the service.
 * This is the **only** place that (re)starts loopback proxies: screens only
 * write to the database.
 */
class LoopbackCoordinator(
    private val context: Context,
    private val repo: ConfigRepository,
    private val auditDao: AuditDao,
) {
    /** Fingerprint of the fields the Rust core copies when the proxy starts:
     *  editing any of them requires a restart (port, host, sni, package,
     *  token, key, certs...). A change of `enabled` already triggers a
     *  start/stop, so it does not need to be hashed. */
    private data class ConfigFingerprint(
        val id: String,
        val targetPackage: String,
        val upstreamHost: String,
        val upstreamPort: Int,
        val sni: String?,
        val loopbackPort: Int?,
        val pathToken: String?,
        val keystoreAlias: String,
        val extraCanonicalHosts: String?,
        val caPemSha256: String,
        val certChainPemSha256: String,
    )

    private fun ConfigEntity.fingerprint() = ConfigFingerprint(
        id = id,
        targetPackage = targetPackage,
        upstreamHost = upstreamHost,
        upstreamPort = upstreamPort,
        sni = sni,
        loopbackPort = loopbackPort,
        pathToken = pathToken,
        keystoreAlias = keystoreAlias,
        extraCanonicalHosts = extraCanonicalHosts,
        caPemSha256 = sha256(caPem),
        certChainPemSha256 = sha256(certChainPem),
    )

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    @Volatile private var lastFingerprints: Map<String, ConfigFingerprint> = emptyMap()
    private val started = AtomicBoolean(false)

    /** Idempotent. Call it from a foreground context (Activity). */
    fun start() {
        if (!started.compareAndSet(false, true)) return
        // Purge audit events older than the sliding window.
        scope.launch { auditDao.purgeOlderThan(System.currentTimeMillis() - AUDIT_RETENTION_MS) }

        scope.launch {
            repo.observeAll()
                .map { list ->
                    list.asSequence()
                        .filter { it.mode == ProxyMode.LOOPBACK && it.enabled }
                        .associate { it.id to it.fingerprint() }
                }
                .distinctUntilChanged()
                .collect { current ->
                    // Pure additions: start.
                    val added = current.keys - lastFingerprints.keys
                    // Pure removals: stop.
                    val removed = lastFingerprints.keys - current.keys
                    // Present on both sides but fingerprint changed: restart
                    // (content edited without a manual off/on toggle).
                    val changed = current.keys.intersect(lastFingerprints.keys)
                        .filter { current[it] != lastFingerprints[it] }

                    // Start refused by the OS (app moved to the background):
                    // not remembered, retried on the next emission.
                    val refused = mutableSetOf<String>()
                    for (id in removed) ProxyLauncher.stopLoopback(context, id)
                    for (id in changed) {
                        ProxyLauncher.stopLoopback(context, id)
                        if (!ProxyLauncher.startLoopback(context, id)) refused += id
                    }
                    for (id in added) {
                        if (!ProxyLauncher.startLoopback(context, id)) refused += id
                    }
                    lastFingerprints = current - refused
                }
        }
    }

    private companion object {
        // 7 days of audit history; anything older is purged on each app start.
        const val AUDIT_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
    }
}
