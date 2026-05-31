package com.douxev.mtls_bridge.runtime

import android.content.Context
import android.net.ConnectivityManager
import android.system.OsConstants
import com.douxev.mtls_bridge.ffi.PeerUidResolver
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Implémente [PeerUidResolver] côté Android en s'appuyant sur
 * `ConnectivityManager.getConnectionOwnerUid(IPPROTO_TCP, peerLocal, peerRemote)`.
 *
 * Convention du trait (depuis le pair) : les paramètres `peerLocal*` /
 * `peerRemote*` sont **déjà du point de vue du pair**, donc aucun swap n'est
 * fait ici. Pour le mode loopback, l'appelant Rust traduit l'inversion ;
 * pour le mode VPN, les addresses arrivent déjà dans le bon sens.
 *
 * Pour les sockets routés via VPN, certains kernels Android ne renvoient pas
 * d'UID (return -1). Côté Rust on traite ce cas en soft-fail (on accepte) car
 * `addAllowedApplication` du VpnService.Builder assure déjà l'isolation au
 * niveau OS.
 */
class AndroidPeerUidResolver(context: Context) : PeerUidResolver {
    private val cm = context.getSystemService(ConnectivityManager::class.java)

    override fun peerUid(
        peerLocalIp: String,
        peerLocalPort: UShort,
        peerRemoteIp: String,
        peerRemotePort: UShort,
    ): UInt? {
        val peerLocal = InetSocketAddress(InetAddress.getByName(peerLocalIp), peerLocalPort.toInt())
        val peerRemote = InetSocketAddress(InetAddress.getByName(peerRemoteIp), peerRemotePort.toInt())
        return try {
            val uid = cm.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, peerLocal, peerRemote)
            if (uid < 0) null else uid.toUInt()
        } catch (_: SecurityException) {
            null
        } catch (_: IllegalArgumentException) {
            // Adresses non-routables refusées par l'OS sur certains devices.
            null
        }
    }
}
