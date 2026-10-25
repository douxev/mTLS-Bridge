package com.douxev.mtls_bridge.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.runtime.AutoStartSettings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Restores the proxies when the device boots and after an app update, unless
 * the user turned "Start on device boot" off: the `enabled` loopback configs,
 * and the VPN tunnel if it was on before (and the VPN consent is still
 * granted). Essential on Android TV: the TV restarts often (deep sleep, power
 * cut) and the user launches Jellyfin straight from the home screen, without
 * opening mTLS Bridge. Starting `specialUse` and `systemExempted` foreground
 * services from BOOT_COMPLETED is allowed.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                if (!AutoStartSettings.startOnBoot(context)) {
                    Log.i(TAG, "${intent.action}: start on boot disabled, nothing restored")
                    return
                }
                Log.i(TAG, "${intent.action}: restoring active proxies")
                (context.applicationContext as MtlsApplication).startLoopbackCoordinator()
                if (AutoStartSettings.vpnWanted(context)) {
                    val started = ProxyLauncher.startVpnFromBoot(context)
                    Log.i(TAG, "VPN tunnel restore requested: $started")
                }
                // The coordinator reads the encrypted database then starts the
                // service asynchronously: keep the process alive long enough
                // for it to do so (the service keeps it alive afterwards).
                val pending = goAsync()
                CoroutineScope(Dispatchers.Default).launch {
                    delay(START_GRACE_MS)
                    pending.finish()
                }
            }
        }
    }

    private companion object {
        const val TAG = "mtls_bridge.boot"
        const val START_GRACE_MS = 8_000L
    }
}
