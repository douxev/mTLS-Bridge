package com.douxev.mtls_bridge.service

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import com.douxev.mtls_bridge.runtime.InstalledApps

/**
 * UI-side orchestrator: decides which service to start for a given config,
 * handles VPN consent when needed, and launches the target app afterwards.
 */
object ProxyLauncher {
    private const val TAG = "mtls_bridge.launcher"

    /**
     * Returns an Intent for `startActivityForResult` if the user has not
     * granted the VPN permission yet, or `null` if everything is already OK.
     * Caller side: if non-null, launch the intent then call [start] again on
     * `RESULT_OK`.
     */
    fun vpnPrepareIntentIfNeeded(context: Context): Intent? =
        VpnService.prepare(context)

    /**
     * Starts / re-enables the loopback proxy for this config (idempotent).
     * Returns false if the OS refuses to start a foreground service (app in
     * the background, Android 12+); never throws.
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
            // ForegroundServiceStartNotAllowedException (API 31+) is a subclass of it.
            Log.w(TAG, "start of proxy $configId refused: ${e.message}")
            false
        }
    }

    /** Stops the loopback proxy of this config (idempotent). */
    fun stopLoopback(context: Context, configId: String) {
        val intent = Intent(context, LoopbackProxyService::class.java).apply {
            action = LoopbackProxyService.ACTION_STOP_FOR
            putExtra(LoopbackProxyService.EXTRA_CONFIG_ID, configId)
        }
        // startService rather than startForegroundService: a stop does not need
        // to show the notification. Allowed while the service runs in the
        // foreground (the app then counts as "in the foreground"); refused only
        // when the app is in the background with no running service, hence no
        // proxy to stop.
        try {
            context.startService(intent)
        } catch (e: IllegalStateException) {
            Log.d(TAG, "stop of proxy $configId ignored (service not running): ${e.message}")
        }
    }

    /**
     * Starts the global VPN (aggregates every VPN-mode config). Called from the
     * UI (app in the foreground): startService is enough, and the service does
     * not crash if the OS then refuses to move it to the foreground.
     */
    fun startVpnGlobal(context: Context) {
        try {
            context.startService(Intent(context, MtlsVpnService::class.java))
        } catch (e: IllegalStateException) {
            Log.w(TAG, "VPN start refused: ${e.message}")
        }
    }


    /** Shuts down the tun then the service (stopService alone leaves the tun bound by the OS). */
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
     * Tries to launch the target app right after the proxy is enabled (phone
     * or Android TV launcher). If the app exposes no launchable activity, this
     * is a silent no-op.
     */
    fun launchTargetApp(context: Activity, packageName: String) {
        val launch = InstalledApps.launchIntent(context.packageManager, packageName) ?: return
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(launch)
    }
}
