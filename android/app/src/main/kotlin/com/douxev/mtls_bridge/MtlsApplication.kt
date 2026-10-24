package com.douxev.mtls_bridge

import android.app.Application
import com.douxev.mtls_bridge.data.AppDatabase
import com.douxev.mtls_bridge.data.ConfigRepository
import com.douxev.mtls_bridge.keystore.AndroidKeystoreSigner
import com.douxev.mtls_bridge.keystore.DbPassphraseProvider
import com.douxev.mtls_bridge.runtime.AndroidPeerUidResolver
import com.douxev.mtls_bridge.runtime.LoopbackCoordinator

/**
 * Conteneur des singletons partagés. On évite Hilt côté MVP pour ne pas
 * ajouter une dépendance de compilation lourde — DI manuelle via Application,
 * récupéré par les Activity et ViewModels via `(application as MtlsApplication)`.
 */
class MtlsApplication : Application() {

    private val coordinator by lazy {
        LoopbackCoordinator(this, configRepo, db.auditDao())
    }

    override fun onCreate() {
        super.onCreate()
        // Active le logger Rust → adb logcat tag "mtls_bridge.rust".
        com.douxev.mtls_bridge.ffi.initLogging()
        // Pas de coordinator.start() ici : le process peut avoir été lancé en
        // arrière-plan (receiver de notification, restart sticky du service) et
        // Android 12+ y interdit startForegroundService
        // (ForegroundServiceStartNotAllowedException). Le restart sticky est
        // géré par LoopbackProxyService lui-même.
    }

    /**
     * Lance/coupe les services loopback en suivant le flag `enabled` des
     * configs. Appelé par MainActivity (premier plan garanti) : à la première
     * ouverture après reboot du device, ça redémarre tous les loopbacks qui
     * étaient enabled. Idempotent.
     */
    fun startLoopbackCoordinator() {
        coordinator.start()
    }

    val db: AppDatabase by lazy {
        val passphrase = DbPassphraseProvider(this).obtainPassphrase()
        AppDatabase.get(this, passphrase)
    }

    val configRepo: ConfigRepository by lazy {
        ConfigRepository(db.configDao())
    }

    val keystoreSigner by lazy { AndroidKeystoreSigner() }

    val peerUidResolver by lazy { AndroidPeerUidResolver(this) }

    /**
     * État global d'activation du tunnel VPN. Set par MtlsVpnService.onCreate
     * et clear par onDestroy. Observé par la liste pour piloter le toggle.
     */
    val vpnRunning: kotlinx.coroutines.flow.MutableStateFlow<Boolean> =
        kotlinx.coroutines.flow.MutableStateFlow(false)
}
