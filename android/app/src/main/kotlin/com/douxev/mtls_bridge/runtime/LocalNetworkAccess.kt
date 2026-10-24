package com.douxev.mtls_bridge.runtime

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.douxev.mtls_bridge.BuildConfig
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Protection « réseau local » d'Android 17 (API 37) : une app ciblant 37 ne
 * peut plus joindre une adresse du LAN sans la permission runtime
 * ACCESS_LOCAL_NETWORK. Un backend self-hosted en 192.168.x.x / 10.x.x.x
 * (upstream du proxy) est exactement ce cas.
 *
 * Définition des plages : developer.android.com/privacy-and-security/local-network-definition
 * (RFC 1918, link-local, CGNAT 100.64/10, multicast/broadcast ; ULA IPv6).
 */
object LocalNetworkAccess {
    private const val ACCESS_LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
    private const val API_ANDROID_17 = 37

    /**
     * Permission à demander sur cet OS, ou `null` si aucune n'est exigée.
     * Android 16 : la restriction n'existe qu'en opt-in de test
     * (`adb shell am compat enable RESTRICT_LOCAL_NETWORK <pkg>`) et se lève
     * avec NEARBY_WIFI_DEVICES — déclarée uniquement dans le manifest debug,
     * pour ne pas imposer un prompt inutile aux builds release.
     */
    fun runtimePermission(): String? = when {
        Build.VERSION.SDK_INT >= API_ANDROID_17 -> ACCESS_LOCAL_NETWORK
        Build.VERSION.SDK_INT == Build.VERSION_CODES.BAKLAVA && BuildConfig.DEBUG ->
            Manifest.permission.NEARBY_WIFI_DEVICES
        else -> null
    }

    fun isGranted(context: Context): Boolean {
        val permission = runtimePermission() ?: return true
        return ContextCompat.checkSelfPermission(context, permission) ==
            PackageManager.PERMISSION_GRANTED
    }

    /** Vrai si au moins un hôte se résout en adresse du réseau local. */
    suspend fun anyResolvesToLocal(hosts: Collection<String>): Boolean =
        withContext(Dispatchers.IO) {
            hosts.map(::bareHost).filter { it.isNotBlank() }.distinct().any { host ->
                // DNS vers un résolveur local (port 53) reste autorisé par l'OS.
                runCatching { InetAddress.getAllByName(host).any(::isLocalAddress) }
                    .getOrDefault(false)
            }
        }

    /** Saisie UI brute ("https://nas.lan:8443/x") → nom résolvable ("nas.lan"). */
    private fun bareHost(input: String): String {
        val h = input.trim().substringAfter("://").substringBefore('/')
        return when {
            h.startsWith("[") -> h.substringAfter('[').substringBefore(']')
            h.count { it == ':' } > 1 -> h // IPv6 littérale sans crochets
            else -> h.substringBefore(':')
        }
    }

    fun isLocalAddress(addr: InetAddress): Boolean {
        if (addr.isLoopbackAddress || addr.isAnyLocalAddress) return false
        if (addr.isLinkLocalAddress || addr.isMulticastAddress) return true
        val b = addr.address
        return when (addr) {
            is Inet4Address -> {
                val o0 = b[0].toInt() and 0xff
                val o1 = b[1].toInt() and 0xff
                addr.isSiteLocalAddress || // 10/8, 172.16/12, 192.168/16
                    (o0 == 100 && o1 in 64..127) || // CGNAT 100.64/10
                    b.all { it == 0xff.toByte() } // broadcast
            }
            is Inet6Address -> (b[0].toInt() and 0xfe) == 0xfc // ULA fc00::/7
            else -> false
        }
    }
}
