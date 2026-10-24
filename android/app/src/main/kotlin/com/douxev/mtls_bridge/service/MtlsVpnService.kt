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
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.data.SyntheticEndpoints
import com.douxev.mtls_bridge.ffi.ProxyConfigSpec
import com.douxev.mtls_bridge.ffi.VpnHandle
import com.douxev.mtls_bridge.ffi.VpnRouteSpec
import com.douxev.mtls_bridge.ffi.startVpnProxy
import com.douxev.mtls_bridge.runtime.AuditLoggerImpl
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
 * VPN locale qui sert N configs simultanément. Pour chacune :
 *  - addAllowedApplication(targetPackage) → seul l'UID de cette app peut
 *    écrire des paquets dans le tun.
 *  - addRoute(synthetic_ip/32) → seul l'IP synthétique de la config est
 *    routée vers nous.
 *  - VpnRouteSpec(ip, port, ProxyConfigSpec) côté Rust → table de routage.
 *
 * Arrêt : `ACTION_STOP` (bouton de la liste ou de la notification) ou
 * `onRevoke()`. Un simple stopService() ne suffit pas : tant que le tun est
 * ouvert, le système reste lié au service et onDestroy n'est jamais appelé.
 */
class MtlsVpnService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    /** Sérialise boot/arrêt : un second onStartCommand attend la fin du premier. */
    private val tunnelMutex = Mutex()
    // Gardés par `synchronized(this)` : onDestroy (main) peut croiser boot (IO).
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
                // Le scope n'a pas de handler : une exception non rattrapée
                // ferait planter tout le process.
                try {
                    boot(startId)
                } catch (e: CancellationException) {
                    throw e
                } catch (t: Throwable) {
                    Log.e(TAG, "boot VPN en échec : ${t.message}", t)
                    failBoot(startId)
                }
            }
        }
        return START_NOT_STICKY
    }

    /** Consentement retiré (réglages) ou autre app VPN activée. */
    override fun onRevoke() {
        scope.launch {
            tunnelMutex.withLock { stopTunnel() }
            (application as MtlsApplication).vpnRunning.value = false
        }
        super.onRevoke() // stopSelf()
    }

    private fun startInForeground() {
        val n = ProxyNotifications.buildVpn(
            this,
            title = "Tunnel mTLS",
            text = "VPN locale active — tape Arrêter pour stopper",
        )
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                // systemExempted : type prévu pour les apps VPN dont le
                // consentement VpnService.prepare() est accordé.
                startForeground(
                    ProxyNotifications.VPN_NOTIFICATION_ID,
                    n,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED,
                )
            } else {
                startForeground(ProxyNotifications.VPN_NOTIFICATION_ID, n)
            }
        } catch (e: RuntimeException) {
            // Démarré par startService (cf. ProxyLauncher) : pas de crash si
            // l'OS refuse, le tun lié par le système garde le service en vie.
            Log.e(TAG, "startForeground refusé : ${e.message}", e)
        }
    }

    private suspend fun boot(startId: Int) {
        // onStartCommand rappelé (toggle, always-on…) : on coupe l'ancien tun
        // et son handle avant d'en établir un nouveau, jamais deux en parallèle.
        stopTunnel()

        val app = application as MtlsApplication
        val configs: List<ConfigEntity> = app.configRepo.observeAll()
            .first()
            .filter { it.mode == ProxyMode.VPN && !it.needsKeystoreRefresh }
        Log.i(TAG, "boot: ${configs.size} config(s) VPN trouvée(s)")
        val routes = buildRoutes(configs)
        if (routes.isEmpty()) {
            Log.e(TAG, "aucune route VPN valide — la VPN ne servirait à rien. Stop.")
            failBoot(startId)
            return
        }

        // On place tun-address ET destinations dans le MÊME /24, sinon le kernel
        // peut refuser de livrer les SYN-ACK (source 192.0.2.X non considérée
        // comme locale au tun). Le /24 sur la totalité de TEST-NET garantit
        // que tout le sous-réseau est routé via notre tun.
        val builder = Builder()
            .setSession("mTLS Wrapper")
            .setMtu(mtu)
            .addAddress(SyntheticEndpoints.TUN_LOCAL_IP, SyntheticEndpoints.TUN_PREFIX)
            .addRoute(SyntheticEndpoints.TUN_NET, SyntheticEndpoints.TUN_PREFIX)
            // Le tun ne transporte que du trafic local vers 192.0.2.0/24 : il ne
            // doit pas faire passer le réseau sous-jacent pour « mesuré ».
            .setMetered(false)
            .setBlocking(false)
        var allowedCount = 0
        configs.map { it.targetPackage }.distinct().forEach { pkg ->
            val pkgAdded = runCatching { builder.addAllowedApplication(pkg) }
            Log.i(TAG, "addAllowedApplication('$pkg') -> ${pkgAdded.isSuccess}")
            if (pkgAdded.isSuccess) allowedCount++
        }
        if (allowedCount == 0) {
            Log.e(TAG, "AUCUNE app autorisée — la VPN ne servirait à rien. Stop.")
            failBoot(startId)
            return
        }
        val pfd = try {
            builder.establish()
        } catch (e: RuntimeException) {
            Log.e(TAG, "establish() a échoué : ${e.message}", e)
            null
        }
        if (pfd == null) {
            Log.e(TAG, "VpnService.establish() returned null — permission VPN refusée ?")
            failBoot(startId)
            return
        }
        // Identité du fichier tun, pour savoir après coup si le core a déjà
        // fermé le fd (voir closeTunFdIfStillOpen).
        val tunStat = try {
            Os.fstat(pfd.fileDescriptor)
        } catch (e: ErrnoException) {
            Log.e(TAG, "fstat du tun : ${e.message}", e)
            pfd.close()
            failBoot(startId)
            return
        }
        val fd = pfd.detachFd()
        Log.i(
            TAG,
            "tun établi, fd=$fd, route ${SyntheticEndpoints.TUN_NET}/${SyntheticEndpoints.TUN_PREFIX}, " +
                "addresses=${SyntheticEndpoints.TUN_LOCAL_IP}/${SyntheticEndpoints.TUN_PREFIX}",
        )

        // Un seul audit logger pour tous les événements VPN ; il dispatch par
        // configId présent dans l'événement (ou broadcast si null).
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
            // Le core n'adopte le fd qu'après avoir validé routes et PEM : sur
            // ces erreurs il reste ouvert et le tun avec lui → on le ferme.
            Log.e(TAG, "startVpnProxy a throw : ${t.message}", t)
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
        Log.i(TAG, "startVpnProxy OK — ${routes.size} route(s) actives")
    }

    private fun buildRoutes(configs: List<ConfigEntity>): List<VpnRouteSpec> {
        val seen = mutableSetOf<Pair<String, Int>>()
        return configs.mapNotNull { cfg ->
            if (cfg.targetPackage.isBlank()) {
                Log.e(TAG, "config '${cfg.id}' (${cfg.displayName}) sans targetPackage — ignorée")
                return@mapNotNull null
            }
            val ip = cfg.syntheticIp?.trim()
            val port = cfg.syntheticPort
            // Le core refuse TOUTE la table pour une seule route invalide ou en
            // double : on écarte la route fautive plutôt que de perdre la VPN.
            if (!SyntheticEndpoints.isValidIp(ip) || port == null || port !in 1..65535) {
                Log.e(TAG, "config '${cfg.id}' : IP/port synthétique invalide ($ip:$port) — ignorée")
                return@mapNotNull null
            }
            if (!seen.add(ip!! to port)) {
                Log.e(TAG, "config '${cfg.id}' : $ip:$port déjà routé — ignorée")
                return@mapNotNull null
            }
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
                    // VPN ne supporte pas le token-in-path (l'URL est déjà
                    // synthétique 192.0.2.X et l'isolation OS-enforced suffit).
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
     * Ferme le fd du tun si le core ne l'a pas adopté. On compare l'identité
     * du fichier (dev/ino/rdev) via un dup : si le core l'a déjà fermé, le
     * numéro peut avoir été réattribué à un autre fichier qu'il ne faut
     * surtout pas fermer (double close).
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
                .onFailure { Log.w(TAG, "fermeture du fd tun $fd : ${it.message}") }
        }
    }

    /** Arrête le core (qui ferme le tun) et l'audit. Idempotent. */
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
