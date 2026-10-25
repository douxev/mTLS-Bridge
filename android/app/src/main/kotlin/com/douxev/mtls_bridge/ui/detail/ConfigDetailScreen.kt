package com.douxev.mtls_bridge.ui.detail

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.data.AuditEventEntity
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.runtime.SafFileUtils
import com.douxev.mtls_bridge.service.ProxyLauncher
import com.douxev.mtls_bridge.data.clientUrl
import com.douxev.mtls_bridge.ui.common.BadgeRow
import com.douxev.mtls_bridge.ui.common.launchOrExplain
import com.douxev.mtls_bridge.ui.tv.LocalIsTv
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfigDetailScreen(
    onBack: () -> Unit,
    vm: ConfigDetailViewModel = viewModel(factory = ConfigDetailViewModel.Factory),
) {
    val config by vm.config.collectAsStateWithLifecycle()
    val events by vm.recentEvents.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(config?.displayName ?: stringResource(R.string.detail_title_fallback)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.common_back))
                    }
                },
            )
        },
    ) { padding ->
        val cfg = config
        if (cfg == null) {
            LoadingState(padding)
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    // Passphrase field of ReimportKeyCard: reserve the keyboard height.
                    .consumeWindowInsets(padding)
                    .imePadding(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                item { ConfigSummaryCard(cfg) }
                if (cfg.needsKeystoreRefresh) {
                    item { ReimportKeyCard(vm) }
                } else {
                    item { LaunchControls(cfg) }
                }
                item {
                    Text(
                        stringResource(R.string.detail_recent_events),
                        style = MaterialTheme.typography.titleSmall,
                    )
                }
                if (events.isEmpty()) {
                    item {
                        Text(
                            stringResource(R.string.detail_no_events),
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                } else {
                    items(events, key = { it.id }) { ev -> EventRow(ev) }
                }
            }
        }
    }
}

@Composable
private fun LoadingState(padding: PaddingValues) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(stringResource(R.string.detail_loading))
    }
}

@Composable
private fun ConfigSummaryCard(cfg: ConfigEntity) {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(cfg.targetPackage, style = MaterialTheme.typography.bodyMedium)
            Text(
                stringResource(R.string.detail_upstream, "${cfg.upstreamHost}:${cfg.upstreamPort}"),
                style = MaterialTheme.typography.bodyMedium,
            )
            cfg.sni?.let {
                Text(stringResource(R.string.detail_sni, it), style = MaterialTheme.typography.bodySmall)
            }
            ClientUrlRow(cfg = cfg, onCopy = { url -> copyToClipboard(context, url) })
            androidx.compose.foundation.layout.Spacer(Modifier.padding(top = 4.dp))
            BadgeRow(level = cfg.securityLevel, mode = cfg.mode)
        }
    }
}

@Composable
private fun ClientUrlRow(cfg: ConfigEntity, onCopy: (String) -> Unit) {
    // Port 0 = ephemeral: the actual port is only known at BIND_OK.
    val url: String? = cfg.clientUrl()
    val isTv = LocalIsTv.current
    androidx.compose.foundation.layout.Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                stringResource(R.string.detail_client_url_label),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                url ?: stringResource(R.string.detail_ephemeral_port),
                // On TV the URL is copied by hand into the target app: show it large.
                style = if (isTv) MaterialTheme.typography.headlineSmall
                else MaterialTheme.typography.bodyMedium,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
            )
        }
        // No useful clipboard on TV (no app to paste into).
        if (url != null && !isTv) {
            IconButton(onClick = { onCopy(url) }) {
                Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.detail_copy_url))
            }
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val mgr = context.getSystemService(ClipboardManager::class.java)
    mgr.setPrimaryClip(ClipData.newPlainText("mTLS Bridge URL", text))
    // On Android 13+ the OS shows its own system toast, so none is added.
    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
        Toast.makeText(context, context.getString(R.string.detail_copied, text), Toast.LENGTH_SHORT).show()
    }
}

@Composable
private fun LaunchControls(cfg: ConfigEntity) {
    val context = LocalContext.current
    val activity = context as? Activity
    when (cfg.mode) {
        ProxyMode.VPN -> {
            // In VPN mode the tunnel is controlled globally from the list
            // (global toggle). Here there is only a shortcut to open the target
            // app once the tunnel is active.
            Button(
                onClick = {
                    activity?.let { ProxyLauncher.launchTargetApp(it, cfg.targetPackage) }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = cfg.targetPackage.isNotBlank(),
            ) {
                Text(
                    stringResource(
                        if (cfg.targetPackage.isBlank()) R.string.detail_no_target_app
                        else R.string.detail_open_app
                    )
                )
            }
        }
        ProxyMode.LOOPBACK -> {
            // The loopback proxy runs permanently while the config is
            // `enabled`, controlled by the card's switch in the list.
            // Here there is only a shortcut to open the target app.
            Button(
                onClick = {
                    activity?.let { ProxyLauncher.launchTargetApp(it, cfg.targetPackage) }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = cfg.targetPackage.isNotBlank() && cfg.enabled,
            ) {
                Text(
                    stringResource(
                        when {
                            cfg.targetPackage.isBlank() -> R.string.detail_no_target_app
                            !cfg.enabled -> R.string.detail_config_disabled
                            else -> R.string.detail_open_app
                        }
                    )
                )
            }
        }
    }
}

@Composable
private fun ReimportKeyCard(vm: ConfigDetailViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var p12Uri by remember { mutableStateOf<android.net.Uri?>(null) }
    var passphrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var deleteAfter by remember { mutableStateOf(false) }
    val pickP12 = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) p12Uri = uri
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                stringResource(R.string.detail_missing_key_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                stringResource(R.string.detail_missing_key_text),
                style = MaterialTheme.typography.bodyMedium,
            )
            androidx.compose.foundation.layout.Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                Button(onClick = { pickP12.launchOrExplain(context, "*/*") }) { Text(stringResource(R.string.detail_choose_p12)) }
                Text(
                    p12Uri?.lastPathSegment ?: stringResource(R.string.detail_no_file),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text(stringResource(R.string.common_label_p12_passphrase)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                Checkbox(checked = deleteAfter, onCheckedChange = { deleteAfter = it })
                Text(
                    stringResource(R.string.detail_delete_p12_after),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(
                onClick = {
                    val uri = p12Uri ?: return@Button
                    busy = true; error = null
                    scope.launch {
                        val bytes = runCatching { SafFileUtils.readBytes(context, uri) }.getOrElse {
                            busy = false
                            error = context.getString(R.string.detail_error_read_p12)
                            return@launch
                        }
                        error = vm.reimportKey(bytes, passphrase.toCharArray())
                        busy = false
                        passphrase = ""
                        if (error == null && deleteAfter) {
                            SafFileUtils.deleteIfPossible(context, uri)
                        }
                    }
                },
                enabled = !busy && p12Uri != null,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(if (busy) R.string.detail_importing else R.string.detail_import_key)) }
        }
    }
}

@Composable
private fun EventRow(ev: AuditEventEntity) {
    val fmt = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(ev.eventType, style = MaterialTheme.typography.labelLarge)
                Text(
                    fmt.format(Date(ev.timestampMs)),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (ev.details.isNotBlank()) {
                Text(
                    ev.details,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

