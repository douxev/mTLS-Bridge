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
    // Par défaut loopback : plus sûr (isolation per-config), plus économe
    // (zero CPU au repos, démarre on-demand), et n'occupe pas le slot VPN
    // unique du device. Voir l'écran "Comparaison" accessible via ⓘ.
    val mode: ProxyMode = ProxyMode.LOOPBACK,
    // Remplacés au chargement par le premier couple libre (cf. init) : deux
    // configs VPN sur le même IP:port font échouer toute la VPN.
    val syntheticIp: String = "192.0.2.1",
    val syntheticPort: String = SyntheticEndpoints.DEFAULT_PORT.toString(),
    // Port loopback aléatoire fixe par config (10001..32767) : assez large
    // (~22k ports) pour quasi pas de collision, évite la plage éphémère OS
    // (>=32768) pour ne pas être en concurrence avec elle, et les plages
    // "registered" très utilisées (<10000). La doxev peut éditer si besoin.
    val loopbackPort: String = (10001..32767).random().toString(),
    // Token-in-path : seule isolation effective du loopback (le contrôle par
    // UID y est inopérant) → ON par défaut. Les webviews (Jellyfin Android,
    // Nextcloud) qui chargent des paths absolus sans le préfixe passent grâce
    // au cookie de session que le proxy pose sur la première URL avec token.
    val pathTokenEnabled: Boolean = true,
    val pathToken: String = PathTokenGen.generate(),
    /** Hôtes canoniques additionnels (loopback), séparés par des virgules. */
    val extraCanonicalHosts: String = "",
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

/**
 * Apps lanceables (téléphone ou Android TV) hors apps système, triées par
 * nom. Lent (labels chargés un par un, des centaines d'apps) : toujours hors
 * du main thread.
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
                // Ne pas écraser une saisie faite pendant la requête.
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
                    ?: error("sélectionne un .p12")
                val ca = s.caUri?.let { SafFileUtils.readBytes(app, it) }
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
