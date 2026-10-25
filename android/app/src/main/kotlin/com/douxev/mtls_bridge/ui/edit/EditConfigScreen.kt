package com.douxev.mtls_bridge.ui.edit

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.ui.add.ExtraCanonicalHostsField
import com.douxev.mtls_bridge.ui.common.rememberLocalNetworkGate

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditConfigScreen(
    onBack: () -> Unit,
    onSaved: () -> Unit,
    vm: EditConfigViewModel = viewModel(factory = EditConfigViewModel.Factory),
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val localNetworkGate = rememberLocalNetworkGate()

    LaunchedEffect(state.success) { if (state.success) onSaved() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.edit_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.common_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                // Edge-to-edge: reserve the keyboard height (see AddConfigScreen).
                .consumeWindowInsets(padding)
                .imePadding()
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.edit_cert_notice),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = state.displayName,
                onValueChange = { v -> vm.update { copy(displayName = v) } },
                label = { Text(stringResource(R.string.edit_label_name)) },
                singleLine = true,
                enabled = state.loaded,
                modifier = Modifier.fillMaxWidth(),
            )

            AppPicker(state, vm)

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = state.upstreamHost,
                    onValueChange = { v -> vm.update { copy(upstreamHost = v) } },
                    label = { Text(stringResource(R.string.common_label_upstream_host)) },
                    singleLine = true,
                    enabled = state.loaded,
                    modifier = Modifier.weight(2f),
                )
                OutlinedTextField(
                    value = state.upstreamPort,
                    onValueChange = { v ->
                        vm.update { copy(upstreamPort = v.filter { c -> c.isDigit() }) }
                    },
                    label = { Text(stringResource(R.string.common_label_port)) },
                    singleLine = true,
                    enabled = state.loaded,
                    modifier = Modifier.weight(1f),
                )
            }

            OutlinedTextField(
                value = state.sni,
                onValueChange = { v -> vm.update { copy(sni = v) } },
                label = { Text(stringResource(R.string.common_label_sni)) },
                singleLine = true,
                enabled = state.loaded,
                modifier = Modifier.fillMaxWidth(),
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = state.mode == ProxyMode.VPN,
                    onClick = { vm.update { copy(mode = ProxyMode.VPN) } },
                    label = { Text(stringResource(R.string.common_mode_vpn)) },
                    enabled = state.loaded,
                )
                FilterChip(
                    selected = state.mode == ProxyMode.LOOPBACK,
                    onClick = { vm.update { copy(mode = ProxyMode.LOOPBACK) } },
                    label = { Text(stringResource(R.string.common_mode_loopback)) },
                    enabled = state.loaded,
                )
            }

            if (state.mode == ProxyMode.VPN) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.syntheticIp,
                        onValueChange = { v -> vm.update { copy(syntheticIp = v) } },
                        label = { Text(stringResource(R.string.edit_label_synthetic_ip)) },
                        singleLine = true,
                        enabled = state.loaded,
                        modifier = Modifier.weight(2f),
                    )
                    OutlinedTextField(
                        value = state.syntheticPort,
                        onValueChange = { v ->
                            vm.update { copy(syntheticPort = v.filter { c -> c.isDigit() }) }
                        },
                        label = { Text(stringResource(R.string.common_label_port)) },
                        singleLine = true,
                        enabled = state.loaded,
                        modifier = Modifier.weight(1f),
                    )
                }
            } else {
                OutlinedTextField(
                    value = state.loopbackPort,
                    onValueChange = { v ->
                        vm.update { copy(loopbackPort = v.filter { c -> c.isDigit() }) }
                    },
                    label = { Text(stringResource(R.string.common_label_loopback_port)) },
                    singleLine = true,
                    enabled = state.loaded,
                    modifier = Modifier.fillMaxWidth(),
                )
                EditPathTokenSection(
                    enabled = state.pathTokenEnabled,
                    token = state.pathToken,
                    loaded = state.loaded,
                    onToggle = { v -> vm.update { copy(pathTokenEnabled = v) } },
                    onRegenerate = {
                        vm.update {
                            copy(pathToken = com.douxev.mtls_bridge.data.PathTokenGen.generate())
                        }
                    },
                    previewUrl = if (state.pathTokenEnabled)
                        "http://127.0.0.1:${state.loopbackPort}/${state.pathToken}/"
                    else "http://127.0.0.1:${state.loopbackPort}/",
                )
                ExtraCanonicalHostsField(
                    value = state.extraCanonicalHosts,
                    onValueChange = { v -> vm.update { copy(extraCanonicalHosts = v) } },
                    enabled = state.loaded,
                )
            }

            state.error?.let { err ->
                Text(err, color = MaterialTheme.colorScheme.error)
            }

            Button(
                // The upstream host may change: request the local network
                // permission (Android 17) before the coordinator restarts the proxy.
                onClick = { localNetworkGate.runAfterCheck(listOf(state.upstreamHost)) { vm.submit() } },
                enabled = state.loaded && !state.submitting,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(if (state.submitting) R.string.edit_saving else R.string.edit_save))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppPicker(state: EditConfigUiState, vm: EditConfigViewModel) {
    var expanded by remember { mutableStateOf(false) }
    val current = state.installedApps.firstOrNull { it.packageName == state.targetPackage }
    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            readOnly = true,
            enabled = false,
            value = current?.let { "${it.label}  (${it.packageName})" }
                ?: state.targetPackage.takeIf { it.isNotBlank() }
                ?: stringResource(R.string.common_choose_target_app),
            onValueChange = {},
            label = { Text(stringResource(R.string.common_label_client_app)) },
            trailingIcon = { Icon(Icons.Default.ArrowDropDown, contentDescription = null) },
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = state.loaded) { expanded = true },
        )
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            modifier = Modifier.fillMaxWidth(0.95f),
        ) {
            state.installedApps.forEach { app ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(app.label)
                            Text(
                                app.packageName,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    },
                    onClick = {
                        vm.update { copy(targetPackage = app.packageName) }
                        expanded = false
                    },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EditPathTokenSection(
    enabled: Boolean,
    token: String,
    loaded: Boolean,
    onToggle: (Boolean) -> Unit,
    onRegenerate: () -> Unit,
    previewUrl: String,
) {
    androidx.compose.material3.Card(
        modifier = Modifier.fillMaxWidth(),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                androidx.compose.material3.Switch(
                    checked = enabled,
                    onCheckedChange = onToggle,
                    enabled = loaded,
                )
                Column(modifier = Modifier.padding(start = 8.dp)) {
                    Text(
                        stringResource(R.string.common_path_token_title),
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        stringResource(R.string.edit_path_token_text),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (enabled) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                ) {
                    Text(
                        text = token,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        modifier = Modifier.weight(1f),
                    )
                    androidx.compose.material3.TextButton(
                        onClick = onRegenerate,
                        enabled = loaded,
                    ) { Text(stringResource(R.string.common_regenerate)) }
                }
            }
            Text(
                text = previewUrl,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }
}
