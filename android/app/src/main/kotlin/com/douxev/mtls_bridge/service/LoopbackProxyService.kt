package com.douxev.mtls_bridge.service

import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.data.CanonicalHosts
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.ffi.LoopbackHandle
import com.douxev.mtls_bridge.ffi.ProxyConfigSpec
import com.douxev.mtls_bridge.ffi.startLoopbackProxy
import com.douxev.mtls_bridge.runtime.AuditLoggerImpl
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Service de premier plan qui héberge **N** proxies loopback en parallèle,
 * un par config en mode loopback `enabled`. Reçoit des intents :
 *  - `ACTION_START_FOR` avec `EXTRA_CONFIG_ID` → démarre/ré-active le proxy
 *    de cette config (idempotent : no-op si déjà actif).
 *  - `ACTION_STOP_FOR` avec `EXTRA_CONFIG_ID` → arrête le proxy de cette
 *    config et son AuditLogger.
 *  - intent `null` (redémarrage START_STICKY) → relance les configs enabled.
 *
 * Les commandes passent par une file traitée **une par une** dans l'ordre
 * d'arrivée : un STOP ne peut plus doubler un START encore en cours (proxy
 * orphelin) ni deux START créer deux proxies pour la même config. Quand la
 * map devient vide, `stopSelf(startId)` : n'arrête le service que si aucune
 * commande plus récente n'est arrivée entre-temps.
 */
class LoopbackProxyService : LifecycleService() {

    private data class RunningProxy(
        val handle: LoopbackHandle,
        val audit: AuditLoggerImpl,
    ) {
        fun shutdown() {
            handle.stop()
            // Libère l'objet uniffi tout de suite (Drop côté Rust → abort de
            // la tâche d'accept) au lieu d'attendre le GC.
            handle.close()
            audit.stop()
        }
    }

    private sealed interface Command { val startId: Int }
    private data class Start(val configId: String, override val startId: Int) : Command
    private data class Stop(val configId: String, override val startId: Int) : Command
    private data class Restore(override val startId: Int) : Command
    private data class Noop(override val startId: Int) : Command

    // Modifiée uniquement sur le main thread (consommateur de [commands] et
    // onDestroy) : pas besoin de synchronisation.
    private val proxies = mutableMapOf<String, RunningProxy>()
    private val commands = Channel<Command>(Channel.UNLIMITED)

    override fun onCreate() {
        super.onCreate()
        lifecycleScope.launch {
            for (cmd in commands) {
                try {
                    when (cmd) {
                        is Start -> startProxyFor(cmd.configId)
                        is Stop -> stopProxyFor(cmd.configId)
                        is Restore -> restoreEnabled()
                        is Noop -> Unit
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (t: Throwable) {
                    Log.e(TAG, "commande $cmd en échec : ${t.message}", t)
                }
                if (proxies.isEmpty()) {
                    stopSelf(cmd.startId)
                } else {
                    enterForeground() // rafraîchit le compteur de la notification
                }
            }
        }
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        if (intent == null) {
            // Redémarrage sticky après kill du process : le service se resynchronise
            // seul avec la base. Peut être refusé en arrière-plan (Android 12+).
            if (!enterForeground()) {
                stopSelf(startId)
                return START_NOT_STICKY
            }
            commands.trySend(Restore(startId))
            return START_STICKY
        }
        val configId = intent.getStringExtra(EXTRA_CONFIG_ID)
        val cmd = when {
            configId == null -> Noop(startId)
            intent.action == ACTION_START_FOR -> {
                // Lancé par startForegroundService : startForeground() obligatoire ici.
                enterForeground()
                Start(configId, startId)
            }
            // Lancé par startService : pas de notification pour un simple arrêt.
            intent.action == ACTION_STOP_FOR -> Stop(configId, startId)
            else -> {
                Log.w(TAG, "action inconnue : ${intent.action}")
                Noop(startId)
            }
        }
        commands.trySend(cmd)
        return START_STICKY
    }

    /** @return false si l'OS refuse le passage au premier plan. */
    private fun enterForeground(): Boolean {
        val n = ProxyNotifications.buildLoopback(
            this,
            title = "Proxies mTLS",
            text = "${proxies.size} actif(s)",
        )
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    ProxyNotifications.LOOPBACK_NOTIFICATION_ID,
                    n,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } else {
                startForeground(ProxyNotifications.LOOPBACK_NOTIFICATION_ID, n)
            }
            true
        } catch (e: IllegalStateException) {
            // ForegroundServiceStartNotAllowedException (API 31+) en est une sous-classe.
            Log.w(TAG, "startForeground refusé : ${e.message}")
            false
        }
    }

    private suspend fun restoreEnabled() {
        val app = application as MtlsApplication
        app.configRepo.observeAll().first()
            .filter { it.mode == ProxyMode.LOOPBACK && it.enabled }
            .forEach { startProxyFor(it.id) }
    }

    private suspend fun startProxyFor(configId: String) {
        if (proxies.containsKey(configId)) {
            Log.d(TAG, "proxy $configId déjà actif — no-op")
            return
        }
        val app = application as MtlsApplication
        val cfg = app.configRepo.byId(configId) ?: run {
            Log.e(TAG, "config $configId introuvable, abandon")
            return
        }
        if (cfg.targetPackage.isBlank()) {
            Log.e(TAG, "config $configId sans targetPackage, abandon")
            return
        }
        if (cfg.needsKeystoreRefresh) {
            Log.e(TAG, "config $configId sans clé Keystore, abandon")
            return
        }
        val targetUid = runCatching {
            packageManager.getApplicationInfo(cfg.targetPackage, 0).uid.toUInt()
        }.getOrElse {
            Log.e(TAG, "uid introuvable pour ${cfg.targetPackage}")
            return
        }
        val audit = AuditLoggerImpl(
            allConfigIds = listOf(cfg.id),
            dao = app.db.auditDao(),
        )
        try {
            val handle = startLoopbackProxy(
                config = ProxyConfigSpec(
                    id = cfg.id,
                    upstreamHost = cfg.upstreamHost,
                    upstreamPort = cfg.upstreamPort.toUShort(),
                    sni = cfg.sni,
                    certChainPem = cfg.certChainPem,
                    caPem = cfg.caPem,
                    keystoreAlias = cfg.keystoreAlias,
                    pathToken = cfg.pathToken,
                    extraCanonicalHosts = CanonicalHosts.parse(cfg.extraCanonicalHosts),
                ),
                bindPort = (cfg.loopbackPort ?: 0).toUShort(),
                expectedUid = targetUid,
                signer = app.keystoreSigner,
                uidResolver = app.peerUidResolver,
                audit = audit,
            )
            proxies[configId] = RunningProxy(handle, audit)
            Log.i(TAG, "proxy démarré pour $configId — port=${handle.port()}")
        } catch (e: CancellationException) {
            audit.stop()
            throw e
        } catch (t: Throwable) {
            Log.e(TAG, "échec startLoopbackProxy pour $configId : ${t.message}", t)
            audit.stop()
        }
    }

    private fun stopProxyFor(configId: String) {
        val rp = proxies.remove(configId) ?: return
        rp.shutdown()
        Log.i(TAG, "proxy stoppé pour $configId")
    }

    override fun onDestroy() {
        commands.close()
        for (rp in proxies.values) rp.shutdown()
        proxies.clear()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_CONFIG_ID = "configId"
        const val ACTION_START_FOR = "com.douxev.mtls_bridge.LOOPBACK_START_FOR"
        const val ACTION_STOP_FOR = "com.douxev.mtls_bridge.LOOPBACK_STOP_FOR"
        private const val TAG = "mtls_bridge.lb"
    }
}
