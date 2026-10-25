package com.douxev.mtls_bridge.ui.remote

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.remote.RemoteAdminServer
import kotlinx.coroutines.flow.StateFlow

/**
 * The LAN console lives as long as the "Remote configuration" screen: started
 * when it opens, stopped when it is left (ViewModel destroyed). It survives
 * rotations and short trips to the background.
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
