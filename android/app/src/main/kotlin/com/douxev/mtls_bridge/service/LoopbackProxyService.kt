package com.douxev.mtls_bridge.service

import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.ffi.LoopbackHandle
import com.douxev.mtls_bridge.ffi.ProxyConfigSpec
import com.douxev.mtls_bridge.ffi.startLoopbackProxy
import com.douxev.mtls_bridge.runtime.AuditLoggerImpl
import java.util.Collections
import kotlinx.coroutines.launch

/**
 * Service de premier plan qui héberge **N** proxies loopback en parallèle,
 * un par config en mode loopback `enabled`. Reçoit des intents :
 *  - `ACTION_START_FOR` avec `EXTRA_CONFIG_ID` → démarre/ré-active le proxy
 *    de cette config (idempotent : no-op si déjà actif).
 *  - `ACTION_STOP_FOR` avec `EXTRA_CONFIG_ID` → arrête le proxy de cette
 *    config et son AuditLogger. Si la map devient vide, `stopSelf()`.
 */
class LoopbackProxyService : LifecycleService() {

    private data class RunningProxy(
        val handle: LoopbackHandle,
        val audit: AuditLoggerImpl,
    )

    private val proxies: MutableMap<String, RunningProxy> =
        Collections.synchronizedMap(mutableMapOf())

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        val action = intent?.action
        val configId = intent?.getStringExtra(EXTRA_CONFIG_ID)
        if (configId == null) {
            // Démarrage "vide" (cas restart sticky) — on attend les start
            // explicites via ACTION_START_FOR sans se tuer.
            ensureForeground()
            return START_STICKY
        }
        ensureForeground()
        when (action) {
            ACTION_START_FOR -> lifecycleScope.launch { startProxyFor(configId) }
            ACTION_STOP_FOR -> stopProxyFor(configId)
            else -> Log.w(TAG, "action inconnue : $action")
        }
        return START_STICKY
    }

    private fun ensureForeground() {
        val n = ProxyNotifications.buildLoopback(
            this,
            title = "Proxies mTLS",
            text = "${proxies.size} actif(s)",
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                ProxyNotifications.LOOPBACK_NOTIFICATION_ID,
                n,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(ProxyNotifications.LOOPBACK_NOTIFICATION_ID, n)
        }
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
                ),
                bindPort = (cfg.loopbackPort ?: 0).toUShort(),
                expectedUid = targetUid,
                signer = app.keystoreSigner,
                uidResolver = app.peerUidResolver,
                audit = audit,
            )
            proxies[configId] = RunningProxy(handle, audit)
            Log.i(TAG, "proxy démarré pour $configId — port=${handle.port()}")
            ensureForeground() // refresh notification text
        } catch (t: Throwable) {
            Log.e(TAG, "échec startLoopbackProxy pour $configId : ${t.message}", t)
            audit.stop()
        }
    }

    private fun stopProxyFor(configId: String) {
        val rp = proxies.remove(configId) ?: return
        rp.handle.stop()
        rp.audit.stop()
        Log.i(TAG, "proxy stoppé pour $configId")
        if (proxies.isEmpty()) {
            stopSelf()
        } else {
            ensureForeground()
        }
    }

    override fun onDestroy() {
        synchronized(proxies) {
            for ((_, rp) in proxies) {
                rp.handle.stop()
                rp.audit.stop()
            }
            proxies.clear()
        }
        super.onDestroy()
    }

    companion object {
        const val EXTRA_CONFIG_ID = "configId"
        const val ACTION_START_FOR = "com.douxev.mtls_bridge.LOOPBACK_START_FOR"
        const val ACTION_STOP_FOR = "com.douxev.mtls_bridge.LOOPBACK_STOP_FOR"
        private const val TAG = "mtls_bridge.lb"
    }
}
