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
 * Android 17 (API 37) "local network" protection: without the
 * ACCESS_LOCAL_NETWORK runtime permission, the app can no longer exchange
 * traffic with a LAN address. The docs restrict it to apps targeting 37, but
 * on Pixel 9 Pro / Android 17 it already applies with targetSdk 36, including
 * to responses from a server in the app (LAN admin console): so it is
 * requested as soon as the OS knows about it. A self-hosted backend on
 * 192.168.x.x / 10.x.x.x (proxy upstream) is the same case.
 *
 * Range definitions: developer.android.com/privacy-and-security/local-network-definition
 * (RFC 1918, link-local, CGNAT 100.64/10, multicast/broadcast; IPv6 ULA).
 */
object LocalNetworkAccess {
    private const val ACCESS_LOCAL_NETWORK = "android.permission.ACCESS_LOCAL_NETWORK"
    private const val API_ANDROID_17 = 37

    /**
     * Permission to request on this OS, or `null` if none is required.
     * Android 16: the restriction only exists as a test opt-in
     * (`adb shell am compat enable RESTRICT_LOCAL_NETWORK <pkg>`) and is lifted
     * with NEARBY_WIFI_DEVICES, declared only in the debug manifest so release
     * builds do not get a needless prompt.
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

    /** True if at least one host resolves to a local network address. */
    suspend fun anyResolvesToLocal(hosts: Collection<String>): Boolean =
        withContext(Dispatchers.IO) {
            hosts.map(::bareHost).filter { it.isNotBlank() }.distinct().any { host ->
                // DNS to a local resolver (port 53) is still allowed by the OS.
                runCatching { InetAddress.getAllByName(host).any(::isLocalAddress) }
                    .getOrDefault(false)
            }
        }

    /** Raw UI input ("https://nas.lan:8443/x") to resolvable name ("nas.lan"). */
    private fun bareHost(input: String): String {
        val h = input.trim().substringAfter("://").substringBefore('/')
        return when {
            h.startsWith("[") -> h.substringAfter('[').substringBefore(']')
            h.count { it == ':' } > 1 -> h // IPv6 literal without brackets
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
