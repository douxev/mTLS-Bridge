package com.douxev.mtls_bridge.ui.detail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.data.AuditDao
import com.douxev.mtls_bridge.data.AuditEventEntity
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ConfigRepository
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class ConfigDetailViewModel(
    private val configId: String,
    private val repo: ConfigRepository,
    private val auditDao: AuditDao,
) : ViewModel() {

    private val _config = kotlinx.coroutines.flow.MutableStateFlow<ConfigEntity?>(null)
    val config: StateFlow<ConfigEntity?> = _config

    val recentEvents: StateFlow<List<AuditEventEntity>> =
        auditDao.observeRecent(configId)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    init {
        viewModelScope.launch { _config.value = repo.byId(configId) }
    }

    /** Re-fournit le .p12 pour une config marquée needsKeystoreRefresh.
     *  Renvoie null en cas de succès, sinon le message d'erreur. */
    suspend fun reimportKey(p12Bytes: ByteArray, p12Passphrase: CharArray): String? = try {
        repo.reimportKey(configId, p12Bytes, p12Passphrase)
        _config.value = repo.byId(configId)
        null
    } catch (t: Throwable) {
        t.message ?: t::class.java.simpleName
    }

    companion object {
        const val CONFIG_ID_KEY = "configId"

        val Factory = viewModelFactory {
            initializer {
                val app = this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]
                        as MtlsApplication
                val saved: SavedStateHandle = createSavedStateHandle()
                val id = saved.get<String>(CONFIG_ID_KEY)
                    ?: error("$CONFIG_ID_KEY manquant")
                ConfigDetailViewModel(id, app.configRepo, app.db.auditDao())
            }
        }
    }
}
