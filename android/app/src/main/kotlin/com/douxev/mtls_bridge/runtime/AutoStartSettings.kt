package com.douxev.mtls_bridge.runtime

import android.content.Context
import androidx.core.content.edit

/**
 * Start-on-boot preferences. Not sensitive, so plain SharedPreferences.
 *
 * - [startOnBoot]: whether [com.douxev.mtls_bridge.service.BootReceiver]
 *   restores the proxies after a reboot or an app update (default on: TVs
 *   reboot often and the target app is launched from the home screen).
 * - [vpnWanted]: whether the user left the VPN tunnel on. Set when the user
 *   starts it, cleared when the user stops it or when Android revokes it
 *   (another VPN app took over), so a reboot restores exactly that state.
 */
object AutoStartSettings {
    private const val PREFS = "mtls_bridge_settings"
    private const val KEY_START_ON_BOOT = "start_on_boot"
    private const val KEY_VPN_WANTED = "vpn_wanted"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun startOnBoot(context: Context): Boolean = prefs(context).getBoolean(KEY_START_ON_BOOT, true)

    fun setStartOnBoot(context: Context, enabled: Boolean) =
        prefs(context).edit { putBoolean(KEY_START_ON_BOOT, enabled) }

    fun vpnWanted(context: Context): Boolean = prefs(context).getBoolean(KEY_VPN_WANTED, false)

    fun setVpnWanted(context: Context, wanted: Boolean) =
        prefs(context).edit { putBoolean(KEY_VPN_WANTED, wanted) }
}
