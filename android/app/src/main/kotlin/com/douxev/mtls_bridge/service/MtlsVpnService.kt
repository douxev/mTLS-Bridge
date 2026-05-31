package com.douxev.mtls_bridge.service

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.util.Log
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.ffi.ProxyConfigSpec
import com.douxev.mtls_bridge.ffi.VpnHandle
import com.douxev.mtls_bridge.ffi.VpnRouteSpec
import com.douxev.mtls_bridge.ffi.startVpnProxy
import com.douxev.mtls_bridge.runtime.AuditLoggerImpl
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * VPN locale qui sert N configs simultanément. Pour chacune :
 *  - addAllowedApplication(targetPackage) → seul l'UID de cette app peut
 *    écrire des paquets dans le tun.
 *  - addRoute(synthetic_ip/32) → seul l'IP synthétique de la config est
 *    routée vers nous.
 *  - VpnRouteSpec(ip, port, ProxyConfigSpec) côté Rust → table de routage.
 */
class MtlsVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var handle: VpnHandle? = null
    private var auditLogger: AuditLoggerImpl? = null
    private val mtu = 1500

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onCreate() {
        super.onCreate()
        (application as MtlsApplication).vpnRunning.value = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startInForeground()
        scope.launch { boot() }
        return START_NOT_STICKY
    }

    private fun startInForeground() {
        val n = ProxyNotifications.buildVpn(
            this,
            title = "Tunnel mTLS",
            text = "VPN locale active — tape Arrêter pour stopper",
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                ProxyNotifications.VPN_NOTIFICATION_ID,
                n,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(ProxyNotifications.VPN_NOTIFICATION_ID, n)
        }
    }

    private suspend fun boot() {
        val app = application as MtlsApplication
        val configs: List<ConfigEntity> = app.configRepo.observeAll()
            .first()
            .filter { it.mode == ProxyMode.VPN }
        Log.i(TAG, "boot: ${configs.size} config(s) VPN trouvée(s)")
        if (configs.isEmpty()) {
            stopSelf()
            return
        }

        // On place tun-address ET destinations dans le MÊME /24, sinon le kernel
        // peut refuser de livrer les SYN-ACK (source 192.0.2.X non considérée
        // comme locale au tun). Le /24 sur la totalité de TEST-NET garantit
        // que tout le sous-réseau est routé via notre tun.
        val builder = Builder()
            .setSession("mTLS Wrapper")
            .setMtu(mtu)
            .addAddress(TUN_LOCAL_IP, TUN_PREFIX)
            .addRoute(TUN_NET, TUN_PREFIX)
            .setBlocking(false)
        var allowedCount = 0
        configs.forEach { cfg ->
            if (cfg.targetPackage.isBlank()) {
                Log.e(TAG, "config '${cfg.id}' (${cfg.displayName}) sans targetPackage — ignorée")
                return@forEach
            }
            val pkgAdded = runCatching { builder.addAllowedApplication(cfg.targetPackage) }
            Log.i(TAG, "addAllowedApplication('${cfg.targetPackage}') -> ${pkgAdded.isSuccess}")
            if (pkgAdded.isSuccess) allowedCount++
        }
        if (allowedCount == 0) {
            Log.e(TAG, "AUCUNE app autorisée — la VPN ne servirait à rien. Stop.")
            stopSelf()
            return
        }
        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "VpnService.establish() returned null — permission VPN refusée ?")
            stopSelf()
            return
        }
        val fd = pfd.detachFd()
        Log.i(TAG, "tun établi, fd=$fd, route $TUN_NET/$TUN_PREFIX, " +
                "addresses=$TUN_LOCAL_IP/$TUN_PREFIX")

        val routes = configs.mapNotNull { cfg ->
            val ip = cfg.syntheticIp ?: return@mapNotNull null
            val port = cfg.syntheticPort ?: return@mapNotNull null
            val targetUid = runCatching {
                packageManager.getApplicationInfo(cfg.targetPackage, 0).uid
            }.getOrNull() ?: run {
                Log.e(TAG, "uid introuvable pour ${cfg.targetPackage} — route ignorée")
                return@mapNotNull null
            }
            VpnRouteSpec(
                syntheticIp = ip,
                syntheticPort = port.toUShort(),
                expectedUid = targetUid.toUInt(),
                config = ProxyConfigSpec(
                    id = cfg.id,
                    upstreamHost = cfg.upstreamHost,
                    upstreamPort = cfg.upstreamPort.toUShort(),
                    sni = cfg.sni,
                    certChainPem = cfg.certChainPem,
                    caPem = cfg.caPem,
                    keystoreAlias = cfg.keystoreAlias,
                ),
            )
        }
        // Un seul audit logger pour tous les événements VPN ; il dispatch par
        // configId présent dans l'événement (ou broadcast si null).
        val audit = AuditLoggerImpl(
            allConfigIds = configs.map { it.id },
            dao = app.db.auditDao(),
        )
        auditLogger = audit
        try {
            handle = startVpnProxy(
                tunFd = fd,
                mtu = mtu.toUInt(),
                routes = routes,
                signer = app.keystoreSigner,
                uidResolver = app.peerUidResolver,
                audit = audit,
            )
            Log.i(TAG, "startVpnProxy OK — ${routes.size} route(s) actives")
        } catch (t: Throwable) {
            Log.e(TAG, "startVpnProxy a throw : ${t.message}", t)
            stopSelf()
        }
    }

    override fun onDestroy() {
        handle?.stop()
        handle = null
        auditLogger?.stop()
        auditLogger = null
        scope.cancel()
        (application as MtlsApplication).vpnRunning.value = false
        super.onDestroy()
    }

    private companion object {
        const val TAG = "mtls_bridge.vpn"
        // TEST-NET-1 (RFC 5737) en entier : non routable Internet, espace
        // documentaire — garantit l'absence de collision avec un vrai service.
        const val TUN_LOCAL_IP = "192.0.2.254"
        const val TUN_NET = "192.0.2.0"
        const val TUN_PREFIX = 24
    }
}
