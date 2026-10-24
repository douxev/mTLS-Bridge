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
 * Observe le repo de configs et garde le service [com.douxev.mtls_bridge.service.
 * LoopbackProxyService] synchronisé avec la liste des configs LOOPBACK `enabled`:
 *
 * - À chaque émission du flow `observeAll()`, on calcule le delta entre
 *   l'ensemble actuel et l'ensemble précédent.
 * - Configs ajoutées / activées → `ProxyLauncher.startLoopback(...)`
 * - Configs supprimées / désactivées → `ProxyLauncher.stopLoopback(...)`
 *
 * Idempotent : démarrer un proxy déjà actif est un no-op côté service.
 * C'est le **seul** endroit qui (re)démarre les proxies loopback : les
 * écrans se contentent d'écrire en base.
 */
class LoopbackCoordinator(
    private val context: Context,
    private val repo: ConfigRepository,
    private val auditDao: AuditDao,
) {
    /** Empreinte des champs que le core Rust copie au démarrage du proxy —
     *  toute édition de l'un d'eux demande un restart (port, hôte, sni,
     *  package, token, clé, certs…). enabled change déjà déclenche un
     *  start/stop, pas besoin de le hasher. */
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

    /** Idempotent. À appeler depuis un contexte au premier plan (Activity). */
    fun start() {
        if (!started.compareAndSet(false, true)) return
        // Purge des audit events plus vieux que la fenêtre glissante.
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
                    // Ajouts purs : on démarre.
                    val added = current.keys - lastFingerprints.keys
                    // Retraits purs : on arrête.
                    val removed = lastFingerprints.keys - current.keys
                    // Présents des deux côtés mais fingerprint changé : restart
                    // (édition du contenu sans toggle off/on manuel).
                    val changed = current.keys.intersect(lastFingerprints.keys)
                        .filter { current[it] != lastFingerprints[it] }

                    // Démarrage refusé par l'OS (app passée en arrière-plan) :
                    // non mémorisé, retenté à la prochaine émission.
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
        // 7 jours d'historique audit ; au-delà on purge à chaque démarrage app.
        const val AUDIT_RETENTION_MS = 7L * 24 * 60 * 60 * 1000
    }
}
