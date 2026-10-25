package com.douxev.mtls_bridge.ui.add

import android.app.Application
import android.content.pm.PackageManager
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.douxev.mtls_bridge.BuildConfig
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.data.ConfigRepository
import com.douxev.mtls_bridge.data.NewConfigRequest
import com.douxev.mtls_bridge.data.PathTokenGen
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.data.SyntheticEndpoints
import com.douxev.mtls_bridge.runtime.InstalledApps
import com.douxev.mtls_bridge.runtime.SafFileUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AddConfigUiState(
    val displayName: String = "",
    val targetPackage: String = "",
    val upstreamHost: String = "",
    val upstreamPort: String = "443",
    val sni: String = "",
    // Loopback by default: safer (per-config isolation), lighter (zero CPU
    // when idle, starts on demand), and does not take the device's single VPN
    // slot. See the "Comparison" screen reachable through the info button.
    val mode: ProxyMode = ProxyMode.LOOPBACK,
    // Replaced on load by the first free pair (see init): two VPN configs
    // on the same IP:port make the whole VPN fail.
    val syntheticIp: String = "192.0.2.1",
    val syntheticPort: String = SyntheticEndpoints.DEFAULT_PORT.toString(),
    // Random loopback port, fixed per config (10001..32767): wide enough
    // (~22k ports) for almost no collisions, avoids the OS ephemeral range
    // (>=32768) so as not to compete with it, and the heavily used
    // "registered" ranges (<10000). The user can edit it if needed.
    val loopbackPort: String = (10001..32767).random().toString(),
    // Token-in-path: the only effective isolation for loopback (UID checks
    // do not work there), so ON by default. Webviews (Jellyfin Android,
    // Nextcloud) that load absolute paths without the prefix still work thanks
    // to the session cookie the proxy sets on the first URL with the token.
    val pathTokenEnabled: Boolean = true,
    val pathToken: String = PathTokenGen.generate(),
    /** Additional canonical hosts (loopback), comma-separated. */
    val extraCanonicalHosts: String = "",
    val p12Uri: Uri? = null,
    val caUri: Uri? = null,
    val p12Passphrase: String = "",
    /** If true, contentResolver.delete(uri) is called after the import. */
    val deleteFilesAfterImport: Boolean = false,
    val installedApps: List<InstalledApp> = emptyList(),
    val submitting: Boolean = false,
    val error: String? = null,
    val success: Boolean = false,
)

data class InstalledApp(
    val packageName: String,
    val label: String,
)

/**
 * Launchable apps (phone or Android TV) excluding system apps, sorted by
 * name. Slow (labels loaded one by one, hundreds of apps): always off the
 * main thread.
 */
internal suspend fun loadLaunchableApps(pm: PackageManager): List<InstalledApp> =
    withContext(Dispatchers.IO) {
        InstalledApps.launchable(pm, BuildConfig.APPLICATION_ID)
    }

class AddConfigViewModel(
    private val app: Application,
    private val repo: ConfigRepository,
) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(AddConfigUiState())
    val state: StateFlow<AddConfigUiState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            val apps = loadLaunchableApps(app.packageManager)
            _state.update { it.copy(installedApps = apps) }
        }
        viewModelScope.launch {
            val (ip, port) = repo.allocateSyntheticEndpoint()
            _state.update {
                // Do not overwrite input typed while the request was running.
                if (it.syntheticIp != "192.0.2.1") it
                else it.copy(syntheticIp = ip, syntheticPort = port.toString())
            }
        }
    }

    fun update(transform: AddConfigUiState.() -> AddConfigUiState) {
        _state.update { it.transform() }
    }

    fun submit() {
        val s = _state.value
        if (s.submitting) return
        _state.update { it.copy(submitting = true, error = null) }
        viewModelScope.launch {
            try {
                val p12 = s.p12Uri?.let { SafFileUtils.readBytes(app, it) }
                    ?: error(app.getString(R.string.add_error_no_p12))
                val ca = s.caUri?.let { SafFileUtils.readBytes(app, it) }
                    ?: error(app.getString(R.string.add_error_no_ca))
                val port = s.upstreamPort.toIntOrNull()
                    ?: error(app.getString(R.string.add_error_invalid_upstream_port))
                val req = NewConfigRequest(
                    displayName = s.displayName.trim(),
                    targetPackage = s.targetPackage,
                    upstreamHost = s.upstreamHost.trim(),
                    upstreamPort = port,
                    sni = s.sni.trim().takeIf { it.isNotEmpty() },
                    caPem = ca,
                    mode = s.mode,
                    syntheticIp = s.syntheticIp.takeIf { s.mode == ProxyMode.VPN },
                    syntheticPort = s.syntheticPort.toIntOrNull()
                        ?.takeIf { s.mode == ProxyMode.VPN },
                    loopbackPort = s.loopbackPort.toIntOrNull()
                        ?.takeIf { s.mode == ProxyMode.LOOPBACK },
                    pathToken = s.pathToken.takeIf {
                        s.mode == ProxyMode.LOOPBACK && s.pathTokenEnabled && it.isNotBlank()
                    },
                    extraCanonicalHosts = s.extraCanonicalHosts.takeIf { s.mode == ProxyMode.LOOPBACK },
                    p12Bytes = p12,
                    p12Passphrase = s.p12Passphrase.toCharArray(),
                )
                repo.create(req)
                if (s.deleteFilesAfterImport) {
                    s.p12Uri?.let { SafFileUtils.deleteIfPossible(app, it) }
                    s.caUri?.let { SafFileUtils.deleteIfPossible(app, it) }
                }
                _state.update { it.copy(submitting = false, success = true) }
            } catch (t: Throwable) {
                _state.update {
                    it.copy(submitting = false, error = t.message ?: t::class.java.simpleName)
                }
            }
        }
    }

    companion object {
        val Factory = viewModelFactory {
            initializer {
                val app = this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]
                        as MtlsApplication
                AddConfigViewModel(app, app.configRepo)
            }
        }
    }
}
