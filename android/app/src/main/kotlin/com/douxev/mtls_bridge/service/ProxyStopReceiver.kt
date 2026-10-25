package com.douxev.mtls_bridge.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.douxev.mtls_bridge.MtlsApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Receives the "Stop" action of the foreground notifications and stops the
 * matching service. Not exported: it can only be triggered by our own
 * PendingIntents.
 */
class ProxyStopReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            ProxyNotifications.ACTION_STOP_VPN -> {
                ProxyLauncher.stopVpn(context)
            }
            ProxyNotifications.ACTION_STOP_LOOPBACK -> {
                context.stopService(Intent(context, LoopbackProxyService::class.java))
                // Without this, `enabled` would stay true in the database and
                // the coordinator would restart every proxy on the next launch.
                val app = context.applicationContext as MtlsApplication
                val pending = goAsync()
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        app.configRepo.disableAllLoopback()
                    } catch (t: Throwable) {
                        Log.e("mtls_bridge.stop", "disabling loopbacks: ${t.message}", t)
                    } finally {
                        pending.finish()
                    }
                }
            }
        }
    }
}
