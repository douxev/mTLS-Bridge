package com.douxev.mtls_bridge.ui.add

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Info
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.ui.common.launchOrExplain
import com.douxev.mtls_bridge.ui.common.rememberLocalNetworkGate
import com.douxev.mtls_bridge.ui.tv.LocalIsTv
import com.douxev.mtls_bridge.ui.tv.tvFocusHighlight

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddConfigScreen(
    onBack: () -> Unit,
    onSaved: () -> Unit,
    onCompareModes: () -> Unit,
    onRemoteClick: () -> Unit,
    vm: AddConfigViewModel = viewModel(factory = AddConfigViewModel.Factory),
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val localNetworkGate = rememberLocalNetworkGate()

    LaunchedEffect(state.success) { if (state.success) onSaved() }

    val pickP12 = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) vm.update { copy(p12Uri = uri) }
    }
    val pickCa = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) vm.update { copy(caUri = uri) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.add_title)) },
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
                // Edge-to-edge (mandatory with targetSdk 36): the keyboard no
                // longer resizes the window, so its height is reserved here.
                .consumeWindowInsets(padding)
                .imePadding()
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (LocalIsTv.current) {
                // On TV: there is not always a file picker, and typing with the
                // remote is slow. The web console handles all of this.
                Card(
                    onClick = onRemoteClick,
                    modifier = Modifier.fillMaxWidth().tvFocusHighlight(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer,
                    ),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(stringResource(R.string.add_tv_card_title), style = MaterialTheme.typography.titleMedium)
                        Text(
                            stringResource(R.string.add_tv_card_text),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
            }
            OutlinedTextField(
                value = state.displayName,
                onValueChange = { v -> vm.update { copy(displayName = v) } },
                label = { Text(stringResource(R.string.add_label_name)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            AppPicker(state, vm)

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = state.upstreamHost,
                    onValueChange = { v -> vm.update { copy(upstreamHost = v) } },
                    label = { Text(stringResource(R.string.common_label_upstream_host)) },
                    singleLine = true,
                    modifier = Modifier.weight(2f),
                )
                OutlinedTextField(
                    value = state.upstreamPort,
                    onValueChange = { v -> vm.update { copy(upstreamPort = v.filter { c -> c.isDigit() }) } },
                    label = { Text(stringResource(R.string.common_label_port)) },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
            }

            OutlinedTextField(
                value = state.sni,
                onValueChange = { v -> vm.update { copy(sni = v) } },
                label = { Text(stringResource(R.string.common_label_sni)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            ModeSelector(state, vm, onCompareModes = onCompareModes)

            if (state.mode == ProxyMode.VPN) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.syntheticIp,
                        onValueChange = { v -> vm.update { copy(syntheticIp = v) } },
                        label = { Text(stringResource(R.string.add_label_synthetic_ip)) },
                        singleLine = true,
                        modifier = Modifier.weight(2f),
                    )
                    OutlinedTextField(
                        value = state.syntheticPort,
                        onValueChange = { v -> vm.update { copy(syntheticPort = v.filter { c -> c.isDigit() }) } },
                        label = { Text(stringResource(R.string.common_label_port)) },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                Text(
                    stringResource(R.string.add_vpn_hint, "http://${state.syntheticIp}:${state.syntheticPort}"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                OutlinedTextField(
                    value = state.loopbackPort,
                    onValueChange = { v -> vm.update { copy(loopbackPort = v.filter { c -> c.isDigit() }) } },
                    label = { Text(stringResource(R.string.common_label_loopback_port)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                PathTokenSection(
                    enabled = state.pathTokenEnabled,
                    token = state.pathToken,
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
                )
            }

            FilePickerRow(
                label = stringResource(R.string.add_label_p12),
                fileName = state.p12Uri?.lastPathSegment,
                onPick = { pickP12.launchOrExplain(context, "*/*") },
            )
            OutlinedTextField(
                value = state.p12Passphrase,
                onValueChange = { v -> vm.update { copy(p12Passphrase = v) } },
                label = { Text(stringResource(R.string.common_label_p12_passphrase)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )

            FilePickerRow(
                label = stringResource(R.string.add_label_ca),
                fileName = state.caUri?.lastPathSegment,
                onPick = { pickCa.launchOrExplain(context, "*/*") },
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                Checkbox(
                    checked = state.deleteFilesAfterImport,
                    onCheckedChange = { v -> vm.update { copy(deleteFilesAfterImport = v) } },
                )
                Column {
                    Text(stringResource(R.string.add_delete_files))
                    Text(
                        stringResource(R.string.add_delete_files_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            state.error?.let { err ->
                Text(
                    err,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            Button(
                // A loopback config starts as soon as it is created: the local
                // network permission (Android 17) must be requested first.
                onClick = { localNetworkGate.runAfterCheck(listOf(state.upstreamHost)) { vm.submit() } },
                enabled = !state.submitting,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(if (state.submitting) R.string.add_importing else R.string.common_import))
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppPicker(state: AddConfigUiState, vm: AddConfigViewModel) {
    var expanded by remember { mutableStateOf(false) }
    val current = state.installedApps.firstOrNull { it.packageName == state.targetPackage }
    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            readOnly = true,
            enabled = false, // Prevents the keyboard; the tap is intercepted with clickable.
            value = current?.let { "${it.label}  (${it.packageName})" } ?: stringResource(R.string.common_choose_target_app),
            onValueChange = {},
            label = { Text(stringResource(R.string.common_label_client_app)) },
            trailingIcon = { Icon(Icons.Default.ArrowDropDown, contentDescription = null) },
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = true },
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
private fun ModeSelector(
    state: AddConfigUiState,
    vm: AddConfigViewModel,
    onCompareModes: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        FilterChip(
            selected = state.mode == ProxyMode.LOOPBACK,
            onClick = { vm.update { copy(mode = ProxyMode.LOOPBACK) } },
            label = { Text(stringResource(R.string.add_mode_loopback_recommended)) },
        )
        FilterChip(
            selected = state.mode == ProxyMode.VPN,
            onClick = { vm.update { copy(mode = ProxyMode.VPN) } },
            label = { Text(stringResource(R.string.common_mode_vpn)) },
        )
        IconButton(onClick = onCompareModes) {
            Icon(Icons.Default.Info, contentDescription = stringResource(R.string.add_compare_modes))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PathTokenSection(
    enabled: Boolean,
    token: String,
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
                )
                Column(modifier = Modifier.padding(start = 8.dp)) {
                    Text(
                        stringResource(R.string.common_path_token_title),
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        stringResource(R.string.add_path_token_text),
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
                    androidx.compose.material3.TextButton(onClick = onRegenerate) {
                        Text(stringResource(R.string.common_regenerate))
                    }
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

/** Shared with the edit screen. */
@Composable
internal fun ExtraCanonicalHostsField(
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean = true,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(R.string.add_extra_hosts_label)) },
        supportingText = {
            Text(stringResource(R.string.add_extra_hosts_hint))
        },
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FilePickerRow(label: String, fileName: String?, onPick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = fileName ?: stringResource(R.string.add_no_file),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
        AssistChip(
            onClick = onPick,
            label = { Text(label) },
            colors = AssistChipDefaults.assistChipColors(),
        )
    }
}
