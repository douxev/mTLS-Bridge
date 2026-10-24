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
 * Reçoit l'action "Arrêter" des notifications de premier plan et stoppe le
 * service correspondant. Pas exporté → uniquement déclenchable par nos
 * propres PendingIntent.
 */
class ProxyStopReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            ProxyNotifications.ACTION_STOP_VPN -> {
                ProxyLauncher.stopVpn(context)
            }
            ProxyNotifications.ACTION_STOP_LOOPBACK -> {
                context.stopService(Intent(context, LoopbackProxyService::class.java))
                // Sans ça `enabled` resterait vrai en base et le coordinator
                // relancerait tous les proxies à la prochaine ouverture.
                val app = context.applicationContext as MtlsApplication
                val pending = goAsync()
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        app.configRepo.disableAllLoopback()
                    } catch (t: Throwable) {
                        Log.e("mtls_bridge.stop", "désactivation des loopbacks : ${t.message}", t)
                    } finally {
                        pending.finish()
                    }
                }
            }
        }
    }
}
