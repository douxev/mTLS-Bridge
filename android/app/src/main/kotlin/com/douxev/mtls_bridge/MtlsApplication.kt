package com.douxev.mtls_bridge

import android.app.Application
import com.douxev.mtls_bridge.data.AppDatabase
import com.douxev.mtls_bridge.data.ConfigRepository
import com.douxev.mtls_bridge.keystore.AndroidKeystoreSigner
import com.douxev.mtls_bridge.keystore.DbPassphraseProvider
import com.douxev.mtls_bridge.runtime.AndroidPeerUidResolver
import com.douxev.mtls_bridge.runtime.LoopbackCoordinator

/**
 * Container for shared singletons. Hilt is avoided for the MVP to keep a heavy
 * compile-time dependency out: manual DI through Application, retrieved by
 * Activities and ViewModels via `(application as MtlsApplication)`.
 */
class MtlsApplication : Application() {

    private val coordinator by lazy {
        LoopbackCoordinator(this, configRepo, db.auditDao())
    }

    override fun onCreate() {
        super.onCreate()
        // Enable the Rust logger (adb logcat tag "mtls_bridge.rust").
        com.douxev.mtls_bridge.ffi.initLogging()
        // No coordinator.start() here: the process may have been started in
        // the background (notification receiver, sticky service restart) and
        // Android 12+ forbids startForegroundService there
        // (ForegroundServiceStartNotAllowedException). The sticky restart is
        // handled by LoopbackProxyService itself.
    }

    /**
     * Starts/stops the loopback services according to the configs' `enabled`
     * flag. Called by MainActivity (guaranteed foreground): on the first launch
     * after a device reboot, this restarts every loopback that was enabled.
     * Idempotent.
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
     * Global activation state of the VPN tunnel. Set by MtlsVpnService.onCreate
     * and cleared by onDestroy. Observed by the list screen to drive the toggle.
     */
    val vpnRunning: kotlinx.coroutines.flow.MutableStateFlow<Boolean> =
        kotlinx.coroutines.flow.MutableStateFlow(false)
}
