package com.douxev.mtls_bridge.ui.list

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ConfigRepository
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class ConfigListViewModel(
    private val repo: ConfigRepository,
) : ViewModel() {

    val configs: StateFlow<List<ConfigEntity>> = repo.observeAll()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun delete(id: String) {
        viewModelScope.launch { repo.delete(id) }
    }

    fun setEnabled(id: String, enabled: Boolean) {
        viewModelScope.launch { repo.setEnabled(id, enabled) }
    }

    /** Renvoie le zip exporté à écrire dans un fichier (null=all configs). */
    suspend fun exportToZip(selectedIds: Set<String>?): ByteArray = repo.exportZip(selectedIds)

    suspend fun peekImportZip(zipBytes: ByteArray) = repo.peekZip(zipBytes)

    suspend fun importFromZip(
        zipBytes: ByteArray,
        p12Passphrase: CharArray? = null,
    ) = repo.importZip(zipBytes, p12Passphrase)

    companion object {
        val Factory = viewModelFactory {
            initializer {
                val app = this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]
                        as MtlsApplication
                ConfigListViewModel(app.configRepo)
            }
        }
    }
}
