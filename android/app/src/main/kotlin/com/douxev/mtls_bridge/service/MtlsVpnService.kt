package com.douxev.mtls_bridge.service

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.StructStat
import android.util.Log
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.data.SyntheticEndpoints
import com.douxev.mtls_bridge.ffi.ProxyConfigSpec
import com.douxev.mtls_bridge.ffi.VpnHandle
import com.douxev.mtls_bridge.ffi.VpnRouteSpec
import com.douxev.mtls_bridge.ffi.startVpnProxy
import com.douxev.mtls_bridge.runtime.AuditLoggerImpl
import com.douxev.mtls_bridge.runtime.AutoStartSettings
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Local VPN serving N configs at once. For each of them:
 *  - addAllowedApplication(targetPackage): only this app's UID can write
 *    packets into the tun.
 *  - addRoute(synthetic_ip/32): only the config's synthetic IP is routed to
 *    us.
 *  - VpnRouteSpec(ip, port, ProxyConfigSpec) on the Rust side: routing table.
 *
 * Shutdown: `ACTION_STOP` (button in the list or in the notification) or
 * `onRevoke()`. A plain stopService() is not enough: while the tun is open,
 * the system stays bound to the service and onDestroy is never called.
 */
class MtlsVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    /** Serializes boot/stop: a second onStartCommand waits for the first to finish. */
    private val tunnelMutex = Mutex()
    // Guarded by `synchronized(this)`: onDestroy (main) may overlap boot (IO).
    private var handle: VpnHandle? = null
    private var auditLogger: AuditLoggerImpl? = null
    private var destroyed = false
    private val mtu = 1500

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val app = application as MtlsApplication
        if (intent?.action == ACTION_STOP) {
            scope.launch {
                tunnelMutex.withLock { stopTunnel() }
                app.vpnRunning.value = false
                stopSelf(startId)
            }
            return START_NOT_STICKY
        }
        startInForeground()
        app.vpnRunning.value = true
        scope.launch {
            tunnelMutex.withLock {
                // The scope has no handler: an uncaught exception would crash
                // the whole process.
                try {
                    boot(startId)
                } catch (e: CancellationException) {
                    throw e
                } catch (t: Throwable) {
                    Log.e(TAG, "VPN boot failed: ${t.message}", t)
                    failBoot(startId)
                }
            }
        }
        return START_NOT_STICKY
    }

    /** Consent revoked (settings) or another VPN app enabled. */
    override fun onRevoke() {
        // Another VPN app took over, or the user revoked us: do not bring the
        // tunnel back at the next boot.
        AutoStartSettings.setVpnWanted(this, false)
        scope.launch {
            tunnelMutex.withLock { stopTunnel() }
            (application as MtlsApplication).vpnRunning.value = false
        }
        super.onRevoke() // stopSelf()
    }

    private fun startInForeground() {
        val n = ProxyNotifications.buildVpn(
            this,
            title = getString(R.string.svc_vpn_notif_title),
            text = getString(R.string.svc_vpn_notif_text),
        )
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                // systemExempted: the type intended for VPN apps whose
                // VpnService.prepare() consent has been granted.
                startForeground(
                    ProxyNotifications.VPN_NOTIFICATION_ID,
                    n,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
                )
            } else {
                startForeground(ProxyNotifications.VPN_NOTIFICATION_ID, n)
            }
        } catch (e: RuntimeException) {
            // Started by startService (see ProxyLauncher): no crash if the OS
            // refuses, the tun bound by the system keeps the service alive.
            Log.e(TAG, "startForeground refused: ${e.message}", e)
        }
    }

    private suspend fun boot(startId: Int) {
        // onStartCommand called again (toggle, always-on...): shut down the old
        // tun and its handle before establishing a new one, never two at once.
        stopTunnel()

        val app = application as MtlsApplication
        val configs: List<ConfigEntity> = app.configRepo.observeAll()
            .first()
            .filter { it.mode == ProxyMode.VPN && !it.needsKeystoreRefresh }
        Log.i(TAG, "boot: ${configs.size} VPN config(s) found")
        val routes = buildRoutes(configs)
        if (routes.isEmpty()) {
            Log.e(TAG, "no valid VPN route, the VPN would be useless. Stopping.")
            failBoot(startId)
            return
        }

        // The tun address AND the destinations are put in the SAME /24,
        // otherwise the kernel may refuse to deliver SYN-ACKs (source
        // 192.0.2.X not considered local to the tun). The /24 covering the
        // whole TEST-NET guarantees the entire subnet is routed via our tun.
        val builder = Builder()
            .setSession("mTLS Bridge")
            .setMtu(mtu)
            .addAddress(SyntheticEndpoints.TUN_LOCAL_IP, SyntheticEndpoints.TUN_PREFIX)
            .addRoute(SyntheticEndpoints.TUN_NET, SyntheticEndpoints.TUN_PREFIX)
            // The tun only carries local traffic to 192.0.2.0/24: it must not
            // make the underlying network look "metered".
            .setMetered(false)
            .setBlocking(false)
        var allowedCount = 0
        configs.map { it.targetPackage }.distinct().forEach { pkg ->
            val pkgAdded = runCatching { builder.addAllowedApplication(pkg) }
            Log.i(TAG, "addAllowedApplication('$pkg') -> ${pkgAdded.isSuccess}")
            if (pkgAdded.isSuccess) allowedCount++
        }
        if (allowedCount == 0) {
            Log.e(TAG, "NO allowed app, the VPN would be useless. Stopping.")
            failBoot(startId)
            return
        }
        val pfd = try {
            builder.establish()
        } catch (e: RuntimeException) {
            Log.e(TAG, "establish() failed: ${e.message}", e)
            null
        }
        if (pfd == null) {
            Log.e(TAG, "VpnService.establish() returned null: VPN permission denied?")
            failBoot(startId)
            return
        }
        // Identity of the tun file, to find out later whether the core has
        // already closed the fd (see closeTunFdIfStillOpen).
        val tunStat = try {
            Os.fstat(pfd.fileDescriptor)
        } catch (e: ErrnoException) {
            Log.e(TAG, "fstat of the tun: ${e.message}", e)
            pfd.close()
            failBoot(startId)
            return
        }
        val fd = pfd.detachFd()
        Log.i(
            TAG,
            "tun established, fd=$fd, route ${SyntheticEndpoints.TUN_NET}/${SyntheticEndpoints.TUN_PREFIX}, " +
                "addresses=${SyntheticEndpoints.TUN_LOCAL_IP}/${SyntheticEndpoints.TUN_PREFIX}",
        )

        // A single audit logger for every VPN event; it dispatches by the
        // configId carried by the event (or broadcasts if null).
        val audit = AuditLoggerImpl(
            allConfigIds = configs.map { it.id },
            dao = app.db.auditDao(),
        )
        val started = try {
            startVpnProxy(
                tunFd = fd,
                mtu = mtu.toUInt(),
                routes = routes,
                signer = app.keystoreSigner,
                uidResolver = app.peerUidResolver,
                audit = audit,
            )
        } catch (t: Throwable) {
            // The core only adopts the fd after validating routes and PEM: on
            // these errors it stays open, and the tun with it, so close it.
            Log.e(TAG, "startVpnProxy threw: ${t.message}", t)
            closeTunFdIfStillOpen(fd, tunStat)
            audit.stop()
            failBoot(startId)
            return
        }
        val keep = synchronized(this) {
            if (destroyed) {
                false
            } else {
                handle = started
                auditLogger = audit
                true
            }
        }
        if (!keep) {
            started.stop()
            started.close()
            audit.stop()
            return
        }
        Log.i(TAG, "startVpnProxy OK, ${routes.size} active route(s)")
    }

    private fun buildRoutes(configs: List<ConfigEntity>): List<VpnRouteSpec> {
        val seen = mutableSetOf<Pair<String, Int>>()
        return configs.mapNotNull { cfg ->
            if (cfg.targetPackage.isBlank()) {
                Log.e(TAG, "config '${cfg.id}' (${cfg.displayName}) has no targetPackage, skipped")
                return@mapNotNull null
            }
            val ip = cfg.syntheticIp?.trim()
            val port = cfg.syntheticPort
            // The core rejects the WHOLE table for a single invalid or duplicate
            // route: drop the faulty route rather than lose the VPN.
            if (!SyntheticEndpoints.isValidIp(ip) || port == null || port !in 1..65535) {
                Log.e(TAG, "config '${cfg.id}': invalid synthetic IP/port ($ip:$port), skipped")
                return@mapNotNull null
            }
            if (!seen.add(ip!! to port)) {
                Log.e(TAG, "config '${cfg.id}': $ip:$port already routed, skipped")
                return@mapNotNull null
            }
            val targetUid = runCatching {
                packageManager.getApplicationInfo(cfg.targetPackage, 0).uid
            }.getOrNull() ?: run {
                Log.e(TAG, "uid not found for ${cfg.targetPackage}, route skipped")
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
                    // VPN does not support token-in-path (the URL is already the
                    // synthetic 192.0.2.X and OS-enforced isolation is enough).
                    pathToken = null,
                    extraCanonicalHosts = emptyList(),
                ),
            )
        }
    }

    private fun failBoot(startId: Int) {
        (application as MtlsApplication).vpnRunning.value = false
        stopSelf(startId)
    }

    /**
     * Closes the tun fd if the core did not adopt it. The file identity
     * (dev/ino/rdev) is compared through a dup: if the core already closed it,
     * the number may have been reassigned to another file that must not be
     * closed (double close).
     */
    private fun closeTunFdIfStillOpen(fd: Int, tunStat: StructStat) {
        val stillTun = runCatching {
            ParcelFileDescriptor.fromFd(fd).use { dup ->
                val st = Os.fstat(dup.fileDescriptor)
                st.st_dev == tunStat.st_dev && st.st_ino == tunStat.st_ino &&
                    st.st_rdev == tunStat.st_rdev
            }
        }.getOrDefault(false)
        if (stillTun) {
            runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
                .onFailure { Log.w(TAG, "closing tun fd $fd: ${it.message}") }
        }
    }

    /** Stops the core (which closes the tun) and the audit logger. Idempotent. */
    private fun stopTunnel() {
        val (h, a) = synchronized(this) {
            val pair = handle to auditLogger
            handle = null
            auditLogger = null
            pair
        }
        h?.let {
            it.stop()
            it.close()
        }
        a?.stop()
    }

    override fun onDestroy() {
        synchronized(this) { destroyed = true }
        scope.cancel()
        stopTunnel()
        (application as MtlsApplication).vpnRunning.value = false
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.douxev.mtls_bridge.VPN_STOP"
        private const val TAG = "mtls_bridge.vpn"
    }
}
