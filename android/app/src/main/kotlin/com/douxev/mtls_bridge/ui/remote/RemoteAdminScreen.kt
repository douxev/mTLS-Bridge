package com.douxev.mtls_bridge.ui.remote

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.remote.RemoteAdminServer
import com.douxev.mtls_bridge.runtime.LocalNetworkAccess
import com.douxev.mtls_bridge.ui.tv.tvFocusHighlight

/**
 * "Remote configuration" screen: shows the console's HTTPS address, a QR code
 * and the pairing PIN. While it is open the screen stays on (otherwise the
 * Android TV screensaver would hide it in the middle of typing on the
 * computer).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteAdminScreen(
    onBack: () -> Unit,
    vm: RemoteAdminViewModel = viewModel(factory = RemoteAdminViewModel.Factory),
) {
    val status by vm.status.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // Android 17: without ACCESS_LOCAL_NETWORK, the OS blocks the app's
    // responses to other devices on the LAN (observed even with
    // targetSdk 36), so the page never loads in the browser.
    val localNetPermission = remember { LocalNetworkAccess.runtimePermission() }
    var localNetGranted by remember { mutableStateOf(LocalNetworkAccess.isGranted(context)) }
    val requestLocalNet = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> localNetGranted = granted }
    LaunchedEffect(Unit) {
        if (localNetPermission != null && !localNetGranted) requestLocalNet.launch(localNetPermission)
    }
    // Back from system settings: the permission may have been granted there.
    LifecycleResumeEffect(Unit) {
        localNetGranted = LocalNetworkAccess.isGranted(context)
        onPauseOrDispose { }
    }
    val localNet = LocalNetState(
        blocked = localNetPermission != null && !localNetGranted,
        onRequest = { localNetPermission?.let(requestLocalNet::launch) },
        onOpenSettings = {
            context.startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", context.packageName, null),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
        },
    )

    val view = LocalView.current
    DisposableEffect(view) {
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = false }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.remote_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.common_back))
                    }
                },
            )
        },
    ) { padding ->
        val wide = LocalConfiguration.current.screenWidthDp >= 720
        val scroll = rememberScrollState()
        if (wide) {
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp),
                horizontalArrangement = Arrangement.spacedBy(32.dp),
            ) {
                Column(
                    modifier = Modifier.weight(1f).verticalScroll(scroll),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) { Details(status, vm, localNet) }
                status.qrPayload?.takeIf { status.running }?.let { qr ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        QrCode(qr, size = 240.dp)
                        Text(
                            stringResource(R.string.remote_scan_hint),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                    }
                }
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp)
                    .verticalScroll(scroll),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Details(status, vm, localNet)
                status.qrPayload?.takeIf { status.running }?.let { qr ->
                    QrCode(qr, size = 200.dp, modifier = Modifier.align(Alignment.CenterHorizontally))
                }
            }
        }
    }
}

private class LocalNetState(
    val blocked: Boolean,
    val onRequest: () -> Unit,
    val onOpenSettings: () -> Unit,
)

@Composable
private fun ColumnScope.Details(
    status: RemoteAdminServer.Status,
    vm: RemoteAdminViewModel,
    localNet: LocalNetState,
) {
    if (localNet.blocked) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    stringResource(R.string.remote_local_network_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
                Text(
                    stringResource(R.string.remote_local_network_text),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(
                        onClick = localNet.onRequest,
                        modifier = Modifier.tvFocusHighlight(ButtonDefaults.shape),
                    ) { Text(stringResource(R.string.remote_allow)) }
                    OutlinedButton(
                        onClick = localNet.onOpenSettings,
                        modifier = Modifier.tvFocusHighlight(ButtonDefaults.outlinedShape),
                    ) { Text(stringResource(R.string.remote_open_settings)) }
                }
            }
        }
    }
    Text(
        stringResource(R.string.remote_intro),
        style = MaterialTheme.typography.bodyLarge,
    )

    when {
        status.starting -> Text(stringResource(R.string.remote_starting), style = MaterialTheme.typography.bodyLarge)
        !status.running -> {
            Text(
                status.error ?: stringResource(R.string.remote_stopped),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyLarge,
            )
            Button(onClick = vm::restart, modifier = Modifier.tvFocusHighlight(ButtonDefaults.shape)) {
                Text(stringResource(R.string.remote_restart))
            }
        }
        else -> {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(stringResource(R.string.remote_address), style = MaterialTheme.typography.labelLarge)
                    if (status.urls.isEmpty()) {
                        Text(
                            stringResource(R.string.remote_no_address),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    status.urls.forEach { url ->
                        Text(
                            url,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.headlineSmall,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    Text(stringResource(R.string.remote_pin), style = MaterialTheme.typography.labelLarge)
                    Text(
                        status.pin.chunked(3).joinToString(" "),
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 44.sp,
                        letterSpacing = 4.sp,
                    )
                    Text(
                        stringResource(R.string.remote_pin_single_use),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(stringResource(R.string.remote_browser_warning_title), style = MaterialTheme.typography.titleSmall)
                    Text(
                        stringResource(R.string.remote_browser_warning_text),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        status.fingerprint.split(':').take(8).joinToString(":") + "…",
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }

            Text(
                if (status.sessions == 0) {
                    stringResource(R.string.remote_no_browser)
                } else {
                    pluralStringResource(R.plurals.remote_browsers_connected, status.sessions, status.sessions)
                },
                style = MaterialTheme.typography.bodyLarge,
            )
            status.lastActivity?.let {
                Text(stringResource(R.string.remote_last_action, it), style = MaterialTheme.typography.bodyMedium)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(
                    onClick = vm::disconnectAll,
                    enabled = status.sessions > 0,
                    modifier = Modifier.tvFocusHighlight(ButtonDefaults.outlinedShape),
                ) { Text(stringResource(R.string.remote_disconnect_all)) }
            }
            Text(
                stringResource(R.string.remote_auto_stop),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
