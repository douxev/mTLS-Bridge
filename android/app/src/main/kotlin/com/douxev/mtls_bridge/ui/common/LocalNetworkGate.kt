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
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.runtime.LocalNetworkAccess
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * Requests the "local network" permission (Android 17+) before an action that
 * starts a proxy, if one of the upstream hosts resolves to a LAN address.
 * The action runs in every case: a refusal does not block the config, it is
 * only reported (connections to that backend will fail).
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

    /** Check without a user gesture: does not ask again after a refusal. */
    fun checkQuietly(hosts: Collection<String>) {
        if (!refused && hosts.isNotEmpty()) runAfterCheck(hosts)
    }

    internal fun onResult(granted: Boolean) {
        if (!granted) {
            refused = true
            Toast.makeText(
                context,
                context.getString(R.string.common_local_network_denied),
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
