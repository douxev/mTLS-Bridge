package com.douxev.mtls_bridge.service

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import com.douxev.mtls_bridge.runtime.InstalledApps

/**
 * Orchestrateur côté UI : décide quel service démarrer pour une config donnée,
 * gère le consentement VPN si nécessaire, et lance l'app cible derrière.
 */
object ProxyLauncher {
    private const val TAG = "mtls_bridge.launcher"

    /**
     * Renvoie un Intent à `startActivityForResult` si l'utilisatrice n'a pas
     * encore accordé la permission VPN, ou `null` si tout est déjà OK.
     * Côté caller : si non-null, lancer l'intent puis rappeler [start] sur
     * `RESULT_OK`.
     */
    fun vpnPrepareIntentIfNeeded(context: Context): Intent? =
        VpnService.prepare(context)

    /**
     * Démarre / réactive le proxy loopback pour cette config (idempotent).
     * Renvoie false si l'OS refuse le démarrage d'un service de premier plan
     * (app en arrière-plan, Android 12+) — jamais d'exception.
     */
    fun startLoopback(context: Context, configId: String): Boolean {
        val intent = Intent(context, LoopbackProxyService::class.java).apply {
            action = LoopbackProxyService.ACTION_START_FOR
            putExtra(LoopbackProxyService.EXTRA_CONFIG_ID, configId)
        }
        return try {
            ContextCompat.startForegroundService(context, intent)
            true
        } catch (e: IllegalStateException) {
            // ForegroundServiceStartNotAllowedException (API 31+) en est une sous-classe.
            Log.w(TAG, "démarrage du proxy $configId refusé : ${e.message}")
            false
        }
    }

    /** Arrête le proxy loopback de cette config (idempotent). */
    fun stopLoopback(context: Context, configId: String) {
        val intent = Intent(context, LoopbackProxyService::class.java).apply {
            action = LoopbackProxyService.ACTION_STOP_FOR
            putExtra(LoopbackProxyService.EXTRA_CONFIG_ID, configId)
        }
        // startService et non startForegroundService : un arrêt n'a pas à
        // afficher la notification. Autorisé tant que le service tourne au
        // premier plan (l'app compte alors comme « au premier plan ») ; refusé
        // seulement si l'app est en arrière-plan sans service actif, donc sans
        // proxy à arrêter.
        try {
            context.startService(intent)
        } catch (e: IllegalStateException) {
            Log.d(TAG, "arrêt du proxy $configId ignoré (service inactif) : ${e.message}")
        }
    }

    /**
     * Démarre la VPN globale (agrège toutes les configs mode VPN). Appelé
     * depuis l'UI (app au premier plan) : startService suffit, et le service
     * ne plante pas si l'OS refuse ensuite son passage au premier plan.
     */
    fun startVpnGlobal(context: Context) {
        try {
            context.startService(Intent(context, MtlsVpnService::class.java))
        } catch (e: IllegalStateException) {
            Log.w(TAG, "démarrage VPN refusé : ${e.message}")
        }
    }

    /** Coupe le tun puis le service (un stopService seul laisse le tun lié par l'OS). */
    fun stopVpn(context: Context) {
        val intent = Intent(context, MtlsVpnService::class.java)
            .setAction(MtlsVpnService.ACTION_STOP)
        try {
            context.startService(intent)
        } catch (e: IllegalStateException) {
            context.stopService(Intent(context, MtlsVpnService::class.java))
        }
    }

    /**
     * Tente de lancer l'app cible juste après l'activation du proxy (launcher
     * téléphone ou Android TV). Si l'app n'expose pas d'activity lanceable on
     * no-op silencieusement.
     */
    fun launchTargetApp(context: Activity, packageName: String) {
        val launch = InstalledApps.launchIntent(context.packageManager, packageName) ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(launch)
    }
}
