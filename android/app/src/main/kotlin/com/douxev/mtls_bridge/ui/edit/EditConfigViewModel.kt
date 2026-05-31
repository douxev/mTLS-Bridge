package com.douxev.mtls_bridge.ui.edit

import android.app.Application
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.data.ConfigRepository
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.ui.add.InstalledApp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * Édition d'une config existante : on ne touche PAS au certificat ni à la
 * clé Keystore (qui sont liés à l'alias = configId). Pour faire tourner les
 * certs, supprime + recrée. Ici on n'autorise que la modif des métadonnées :
 * nom, app cible, hôte/port upstream, SNI, mode, IP/port synthétique ou
 * port loopback.
 */
data class EditConfigUiState(
    val displayName: String = "",
    val targetPackage: String = "",
    val upstreamHost: String = "",
    val upstreamPort: String = "443",
    val sni: String = "",
    val mode: ProxyMode = ProxyMode.VPN,
    val syntheticIp: String = "192.0.2.1",
    val syntheticPort: String = "5001",
    val loopbackPort: String = "0",
    val installedApps: List<InstalledApp> = emptyList(),
    val loaded: Boolean = false,
    val submitting: Boolean = false,
    val error: String? = null,
    val success: Boolean = false,
)

class EditConfigViewModel(
    private val configId: String,
    private val app: Application,
    private val repo: ConfigRepository,
) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(EditConfigUiState())
    val state: StateFlow<EditConfigUiState> = _state.asStateFlow()

    init {
        viewModelScope.launch {
            val cfg = repo.byId(configId)
            if (cfg == null) {
                _state.update { it.copy(loaded = true, error = "config introuvable") }
                return@launch
            }
            _state.update {
                it.copy(
                    loaded = true,
                    displayName = cfg.displayName,
                    targetPackage = cfg.targetPackage,
                    upstreamHost = cfg.upstreamHost,
                    upstreamPort = cfg.upstreamPort.toString(),
                    sni = cfg.sni.orEmpty(),
                    mode = cfg.mode,
                    syntheticIp = cfg.syntheticIp.orEmpty().ifBlank { "192.0.2.1" },
                    syntheticPort = (cfg.syntheticPort ?: 5001).toString(),
                    loopbackPort = (cfg.loopbackPort ?: 0).toString(),
                )
            }
        }
        loadInstalledApps()
    }

    private fun loadInstalledApps() {
        viewModelScope.launch {
            val pm = app.packageManager
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
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

    fun update(transform: EditConfigUiState.() -> EditConfigUiState) {
        _state.update { it.transform() }
    }

    fun submit() {
        val s = _state.value
        if (s.submitting) return
        _state.update { it.copy(submitting = true, error = null) }
        viewModelScope.launch {
            try {
                repo.updateMetadata(
                    id = configId,
                    displayName = s.displayName.trim(),
                    targetPackage = s.targetPackage,
                    upstreamHost = s.upstreamHost.trim(),
                    upstreamPort = s.upstreamPort.toIntOrNull() ?: error("port invalide"),
                    sni = s.sni.trim().takeIf { it.isNotEmpty() },
                    mode = s.mode,
                    syntheticIp = s.syntheticIp.takeIf { s.mode == ProxyMode.VPN },
                    syntheticPort = s.syntheticPort.toIntOrNull()
                        ?.takeIf { s.mode == ProxyMode.VPN },
                    loopbackPort = s.loopbackPort.toIntOrNull()
                        ?.takeIf { s.mode == ProxyMode.LOOPBACK },
                )
                _state.update { it.copy(submitting = false, success = true) }
            } catch (t: Throwable) {
                _state.update {
                    it.copy(submitting = false, error = t.message ?: t::class.java.simpleName)
                }
            }
        }
    }

    companion object {
        const val CONFIG_ID_KEY = "configId"

        val Factory = viewModelFactory {
            initializer {
                val app = this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]
                        as MtlsApplication
                val saved: SavedStateHandle = createSavedStateHandle()
                val id = saved.get<String>(CONFIG_ID_KEY) ?: error("$CONFIG_ID_KEY manquant")
                EditConfigViewModel(id, app, app.configRepo)
            }
        }
    }
}
