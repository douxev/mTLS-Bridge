package com.douxev.mtls_bridge.ui.remote

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.remote.RemoteAdminServer
import kotlinx.coroutines.flow.StateFlow

/**
 * La console LAN vit aussi longtemps que l'écran « Configuration à
 * distance » : démarrée à l'ouverture, arrêtée quand on le quitte (ViewModel
 * détruit). Elle survit aux rotations et à un passage en arrière-plan bref.
 */
class RemoteAdminViewModel(app: MtlsApplication) : ViewModel() {
    private val server = RemoteAdminServer(app)
    val status: StateFlow<RemoteAdminServer.Status> = server.status

    init {
        server.start()
    }

    fun restart() {
        server.stop()
        server.start()
    }

    fun disconnectAll() = server.disconnectAll()

    override fun onCleared() {
        server.stop()
    }

    companion object {
        val Factory = viewModelFactory {
            initializer {
                val app = this[ViewModelProvider.AndroidViewModelFactory.APPLICATION_KEY]
                    as MtlsApplication
                RemoteAdminViewModel(app)
            }
        }
    }
}
