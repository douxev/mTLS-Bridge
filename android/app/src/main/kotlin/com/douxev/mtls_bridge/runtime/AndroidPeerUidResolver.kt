package com.douxev.mtls_bridge.runtime

import android.content.Context
import android.net.ConnectivityManager
import android.system.OsConstants
import com.douxev.mtls_bridge.ffi.PeerUidResolver
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Android implementation of [PeerUidResolver], built on
 * `ConnectivityManager.getConnectionOwnerUid(IPPROTO_TCP, peerLocal, peerRemote)`.
 *
 * Trait convention (from the peer's side): the `peerLocal*` / `peerRemote*`
 * parameters are **already from the peer's point of view**, so no swap is
 * done here. In loopback mode, the Rust caller handles the inversion; in VPN
 * mode, the addresses already arrive in the right order.
 *
 * For sockets routed through the VPN, some Android kernels return no UID
 * (return -1). The Rust side treats this as a soft failure (accepts) because
 * `addAllowedApplication` on VpnService.Builder already enforces isolation at
 * the OS level.
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
            // Non-routable addresses rejected by the OS on some devices.
            null
        }
    }
}
