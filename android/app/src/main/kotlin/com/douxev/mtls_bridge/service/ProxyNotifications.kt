package com.douxev.mtls_bridge.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.douxev.mtls_bridge.R

internal object ProxyNotifications {
    const val CHANNEL_ID = "mtls_bridge-proxy"
    private const val CHANNEL_NAME = "Proxy mTLS actif"
    const val LOOPBACK_NOTIFICATION_ID = 1001
    const val VPN_NOTIFICATION_ID = 1002

    /** Action broadcast envoyée par le bouton Stop de la notification VPN. */
    const val ACTION_STOP_VPN = "com.douxev.mtls_bridge.STOP_VPN"
    const val ACTION_STOP_LOOPBACK = "com.douxev.mtls_bridge.STOP_LOOPBACK"

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = context.getSystemService(NotificationManager::class.java)
            if (mgr.getNotificationChannel(CHANNEL_ID) == null) {
                mgr.createNotificationChannel(
                    NotificationChannel(
                        CHANNEL_ID,
                        CHANNEL_NAME,
                        NotificationManager.IMPORTANCE_LOW,
                    ).apply {
                        description = "Affichée tant qu'un proxy mTLS tourne en fond"
                    }
                )
            }
        }
    }

    fun buildVpn(context: Context, title: String, text: String): Notification {
        ensureChannel(context)
        val stopIntent = Intent(context, ProxyStopReceiver::class.java).apply {
            action = ACTION_STOP_VPN
            setPackage(context.packageName)
        }
        val stopPI = PendingIntent.getBroadcast(
            context, 0, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Arrêter VPN", stopPI)
            .build()
    }

    fun buildLoopback(context: Context, title: String, text: String): Notification {
        ensureChannel(context)
        val stopIntent = Intent(context, ProxyStopReceiver::class.java).apply {
            action = ACTION_STOP_LOOPBACK
            setPackage(context.packageName)
        }
        val stopPI = PendingIntent.getBroadcast(
            context, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Arrêter", stopPI)
            .build()
    }
}
