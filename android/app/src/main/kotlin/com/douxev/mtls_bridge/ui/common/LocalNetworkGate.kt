package com.douxev.mtls_bridge.ui.common

import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import com.douxev.mtls_bridge.runtime.LocalNetworkAccess
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * Demande la permission « réseau local » (Android 17+) avant une action qui
 * démarre un proxy, si l'un des hôtes upstream se résout en adresse du LAN.
 * L'action s'exécute dans tous les cas : un refus ne bloque pas la config,
 * il est seulement signalé (les connexions vers ce backend échoueront).
 */
class LocalNetworkGate internal constructor(
    private val context: Context,
    private val scope: CoroutineScope,
) {
    internal lateinit var launcher: ActivityResultLauncher<String>
    private var pending: (() -> Unit)? = null
    private var refused = false

    fun runAfterCheck(hosts: Collection<String>, action: () -> Unit = {}) {
        val permission = LocalNetworkAccess.runtimePermission()
        if (permission == null || LocalNetworkAccess.isGranted(context)) {
            action()
            return
        }
        scope.launch {
            if (LocalNetworkAccess.anyResolvesToLocal(hosts)) {
                pending = action
                launcher.launch(permission)
            } else {
                action()
            }
        }
    }

    /** Vérification sans action utilisatrice : ne redemande pas après un refus. */
    fun checkQuietly(hosts: Collection<String>) {
        if (!refused && hosts.isNotEmpty()) runAfterCheck(hosts)
    }

    internal fun onResult(granted: Boolean) {
        if (!granted) {
            refused = true
            Toast.makeText(
                context,
                "Accès au réseau local refusé : le proxy ne pourra pas joindre un " +
                    "backend du LAN. Réglages → Applis → mTLS Bridge → Appareils à proximité.",
                Toast.LENGTH_LONG,
            ).show()
        }
        pending?.invoke()
        pending = null
    }
}

@Composable
fun rememberLocalNetworkGate(): LocalNetworkGate {
    val context = LocalContext.current.applicationContext
    val scope = rememberCoroutineScope()
    val gate = remember { LocalNetworkGate(context, scope) }
    gate.launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
        gate::onResult,
    )
    return gate
}
