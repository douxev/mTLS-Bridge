package com.douxev.mtls_bridge.ui.add

import android.app.Application
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.data.ConfigRepository
import com.douxev.mtls_bridge.data.NewConfigRequest
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.runtime.SafFileUtils
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class AddConfigUiState(
    val displayName: String = "",
    val targetPackage: String = "",
    val upstreamHost: String = "",
    val upstreamPort: String = "443",
    val sni: String = "",
    // Par défaut loopback : plus sûr (isolation per-config), plus économe
    // (zero CPU au repos, démarre on-demand), et n'occupe pas le slot VPN
    // unique du device. Voir l'écran "Comparaison" accessible via ⓘ.
    val mode: ProxyMode = ProxyMode.LOOPBACK,
    val syntheticIp: String = "192.0.2.1",
    val syntheticPort: String = "5001",
    val loopbackPort: String = "0",
    val p12Uri: Uri? = null,
    val caUri: Uri? = null,
    val p12Passphrase: String = "",
    /** Si true, on appellera contentResolver.delete(uri) après l'import. */
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

class AddConfigViewModel(
    private val app: Application,
    private val repo: ConfigRepository,
) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(AddConfigUiState())
    val state: StateFlow<AddConfigUiState> = _state.asStateFlow()

    init {
        loadInstalledApps()
    }

    private fun loadInstalledApps() {
        viewModelScope.launch {
            val pm = app.packageManager
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                // On filtre les apps lanceables (sinon on a 600+ "apps système"
                // sans icône, inutiles à l'utilisatrice).
                .filter { pm.getLaunchIntentForPackage(it.packageName) != null }
                .filter { it.flags and ApplicationInfo.FLAG_SYSTEM == 0 ||
                    it.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0 }
                .map {
                    InstalledApp(
                        packageName = it.packageName,
                        label = pm.getApplicationLabel(it).toString(),
                    )
                }
                .sortedBy { it.label.lowercase() }
            _state.update { it.copy(installedApps = apps) }
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
                val p12 = s.p12Uri?.let { readBytes(it) }
                    ?: error("sélectionne un .p12")
                val ca = s.caUri?.let { readBytes(it) }
                    ?: error("sélectionne un CA pinné")
                val port = s.upstreamPort.toIntOrNull()
                    ?: error("port upstream invalide")
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

    private fun readBytes(uri: Uri): ByteArray =
        app.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: error("impossible de lire $uri")

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
