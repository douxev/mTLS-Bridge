package com.douxev.mtls_bridge.service

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ProxyMode

/**
 * Orchestrateur côté UI : décide quel service démarrer pour une config donnée,
 * gère le consentement VPN si nécessaire, et lance l'app cible derrière.
 */
object ProxyLauncher {

    /**
     * Renvoie un Intent à `startActivityForResult` si l'utilisatrice n'a pas
     * encore accordé la permission VPN, ou `null` si tout est déjà OK.
     * Côté caller : si non-null, lancer l'intent puis rappeler [start] sur
     * `RESULT_OK`.
     */
    fun vpnPrepareIntentIfNeeded(context: Context): Intent? =
        VpnService.prepare(context)

    /** Démarre / réactive le proxy loopback pour cette config (idempotent). */
    fun startLoopback(context: Context, configId: String) {
        val intent = Intent(context, LoopbackProxyService::class.java).apply {
            action = LoopbackProxyService.ACTION_START_FOR
            putExtra(LoopbackProxyService.EXTRA_CONFIG_ID, configId)
        }
        ContextCompat.startForegroundService(context, intent)
    }

    /** Arrête le proxy loopback de cette config (idempotent). */
    fun stopLoopback(context: Context, configId: String) {
        val intent = Intent(context, LoopbackProxyService::class.java).apply {
            action = LoopbackProxyService.ACTION_STOP_FOR
            putExtra(LoopbackProxyService.EXTRA_CONFIG_ID, configId)
        }
        // startForegroundService est obligatoire pour passer l'intent au service
        // même pour un stop quand l'app est en background (sinon ANR sur Android 8+).
        ContextCompat.startForegroundService(context, intent)
    }

    /** Démarre la VPN globale (agrège toutes les configs mode VPN). */
    fun startVpnGlobal(context: Context) {
        val intent = Intent(context, MtlsVpnService::class.java)
        ContextCompat.startForegroundService(context, intent)
    }

    fun stopVpn(context: Context) {
        context.stopService(Intent(context, MtlsVpnService::class.java))
    }

    /**
     * Tente de lancer l'app cible juste après l'activation du proxy. Si l'app
     * n'expose pas d'activity lanceable on no-op silencieusement.
     */
    fun launchTargetApp(context: Activity, packageName: String) {
        val pm = context.packageManager
        val launch = pm.getLaunchIntentForPackage(packageName) ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(launch)
    }
}
