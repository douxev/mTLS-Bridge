package com.douxev.mtls_bridge.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Reçoit l'action "Arrêter" des notifications de premier plan et stoppe le
 * service correspondant. Pas exporté → uniquement déclenchable par nos
 * propres PendingIntent.
 */
class ProxyStopReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        when (intent?.action) {
            ProxyNotifications.ACTION_STOP_VPN -> {
                context.stopService(Intent(context, MtlsVpnService::class.java))
            }
            ProxyNotifications.ACTION_STOP_LOOPBACK -> {
                context.stopService(Intent(context, LoopbackProxyService::class.java))
            }
        }
    }
}
