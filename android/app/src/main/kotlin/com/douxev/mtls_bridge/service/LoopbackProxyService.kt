package com.douxev.mtls_bridge.service

import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.R
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
 * Foreground service hosting **N** loopback proxies in parallel, one per
 * `enabled` loopback-mode config. Handles these intents:
 *  - `ACTION_START_FOR` with `EXTRA_CONFIG_ID`: starts/re-enables the proxy
 *    of this config (idempotent: no-op if already running).
 *  - `ACTION_STOP_FOR` with `EXTRA_CONFIG_ID`: stops the proxy of this config
 *    and its AuditLogger.
 *  - `null` intent (START_STICKY restart): restarts the enabled configs.
 *
 * Commands go through a queue processed **one at a time** in arrival order:
 * a STOP can no longer overtake a START still in progress (orphan proxy), and
 * two STARTs cannot create two proxies for the same config. When the map
 * becomes empty, `stopSelf(startId)` only stops the service if no newer
 * command has arrived in the meantime.
 */
class LoopbackProxyService : LifecycleService() {

    private data class RunningProxy(
        val handle: LoopbackHandle,
        val audit: AuditLoggerImpl,
    ) {
        fun shutdown() {
            handle.stop()
            // Release the uniffi object right away (Drop on the Rust side
            // aborts the accept task) instead of waiting for the GC.
            handle.close()
            audit.stop()
        }
    }

    private sealed interface Command { val startId: Int }
    private data class Start(val configId: String, override val startId: Int) : Command
    private data class Stop(val configId: String, override val startId: Int) : Command
    private data class Restore(override val startId: Int) : Command
    private data class Noop(override val startId: Int) : Command

    // Only modified on the main thread (consumer of [commands] and
    // onDestroy): no synchronization needed.
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
                    Log.e(TAG, "command $cmd failed: ${t.message}", t)
                }
                if (proxies.isEmpty()) {
                    stopSelf(cmd.startId)
                } else {
                    enterForeground() // refreshes the notification counter
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
            // Sticky restart after the process was killed: the service resyncs
            // with the database on its own. May be refused in the background
            // (Android 12+).
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
                // Started by startForegroundService: startForeground() is mandatory here.
                enterForeground()
                Start(configId, startId)
            }
            // Started by startService: no notification for a mere stop.
            intent.action == ACTION_STOP_FOR -> Stop(configId, startId)
            else -> {
                Log.w(TAG, "unknown action: ${intent.action}")
                Noop(startId)
            }
        }
        commands.trySend(cmd)
        return START_STICKY
    }

    /** @return false if the OS refuses to move the service to the foreground. */
    private fun enterForeground(): Boolean {
        val n = ProxyNotifications.buildLoopback(
            this,
            title = getString(R.string.svc_loopback_notif_title),
            text = getString(R.string.svc_loopback_notif_text, proxies.size),
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
            // ForegroundServiceStartNotAllowedException (API 31+) is a subclass of it.
            Log.w(TAG, "startForeground refused: ${e.message}")
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
            Log.d(TAG, "proxy $configId already running, no-op")
            return
        }
        val app = application as MtlsApplication
        val cfg = app.configRepo.byId(configId) ?: run {
            Log.e(TAG, "config $configId not found, giving up")
            return
        }
        if (cfg.targetPackage.isBlank()) {
            Log.e(TAG, "config $configId has no targetPackage, giving up")
            return
        }
        if (cfg.needsKeystoreRefresh) {
            Log.e(TAG, "config $configId has no Keystore key, giving up")
            return
        }
        val targetUid = runCatching {
            packageManager.getApplicationInfo(cfg.targetPackage, 0).uid.toUInt()
        }.getOrElse {
            Log.e(TAG, "uid not found for ${cfg.targetPackage}")
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
            Log.i(TAG, "proxy started for $configId, port=${handle.port()}")
        } catch (e: CancellationException) {
            audit.stop()
            throw e
        } catch (t: Throwable) {
            Log.e(TAG, "startLoopbackProxy failed for $configId: ${t.message}", t)
            audit.stop()
        }
    }

    private fun stopProxyFor(configId: String) {
        val rp = proxies.remove(configId) ?: return
        rp.shutdown()
        Log.i(TAG, "proxy stopped for $configId")
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
