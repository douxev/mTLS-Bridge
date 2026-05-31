package com.douxev.mtls_bridge.ui.add

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.data.ProxyMode

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddConfigScreen(
    onBack: () -> Unit,
    onSaved: () -> Unit,
    onCompareModes: () -> Unit,
    vm: AddConfigViewModel = viewModel(factory = AddConfigViewModel.Factory),
) {
    val state by vm.state.collectAsStateWithLifecycle()

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
                title = { Text("Nouvelle config") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Retour")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            OutlinedTextField(
                value = state.displayName,
                onValueChange = { v -> vm.update { copy(displayName = v) } },
                label = { Text("Nom (Jellyfin, Nextcloud…)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            AppPicker(state, vm)

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = state.upstreamHost,
                    onValueChange = { v -> vm.update { copy(upstreamHost = v) } },
                    label = { Text("Hôte upstream") },
                    singleLine = true,
                    modifier = Modifier.weight(2f),
                )
                OutlinedTextField(
                    value = state.upstreamPort,
                    onValueChange = { v -> vm.update { copy(upstreamPort = v.filter { c -> c.isDigit() }) } },
                    label = { Text("Port") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
            }

            OutlinedTextField(
                value = state.sni,
                onValueChange = { v -> vm.update { copy(sni = v) } },
                label = { Text("SNI (optionnel)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            ModeSelector(state, vm, onCompareModes = onCompareModes)

            if (state.mode == ProxyMode.VPN) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.syntheticIp,
                        onValueChange = { v -> vm.update { copy(syntheticIp = v) } },
                        label = { Text("IP synthétique (192.0.2.X)") },
                        singleLine = true,
                        modifier = Modifier.weight(2f),
                    )
                    OutlinedTextField(
                        value = state.syntheticPort,
                        onValueChange = { v -> vm.update { copy(syntheticPort = v.filter { c -> c.isDigit() }) } },
                        label = { Text("Port") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                Text(
                    "Configure l'app cible avec  http://${state.syntheticIp}:${state.syntheticPort}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                OutlinedTextField(
                    value = state.loopbackPort,
                    onValueChange = { v -> vm.update { copy(loopbackPort = v.filter { c -> c.isDigit() }) } },
                    label = { Text("Port loopback (0 = éphémère)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            FilePickerRow(
                label = "Certificat client (.p12)",
                fileName = state.p12Uri?.lastPathSegment,
                onPick = { pickP12.launch("*/*") },
            )
            OutlinedTextField(
                value = state.p12Passphrase,
                onValueChange = { v -> vm.update { copy(p12Passphrase = v) } },
                label = { Text("Passphrase du .p12") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
            )

            FilePickerRow(
                label = "CA upstream pinné (.pem)",
                fileName = state.caUri?.lastPathSegment,
                onPick = { pickCa.launch("*/*") },
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
                    Text("Supprimer les fichiers .p12 et .pem après import")
                    Text(
                        "Recommandé : la clé est ré-importée dans le Keystore matériel, " +
                            "garder les fichiers en clair sur le filesystem est inutile et risqué.",
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
                onClick = { vm.submit() },
                enabled = !state.submitting,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.submitting) "Import en cours…" else "Importer")
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
            enabled = false, // empêche le clavier ; on intercepte le tap via clickable.
            value = current?.let { "${it.label}  (${it.packageName})" } ?: "Choisir l'app cible",
            onValueChange = {},
            label = { Text("App cliente") },
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
            label = { Text("Loopback (recommandé)") },
        )
        FilterChip(
            selected = state.mode == ProxyMode.VPN,
            onClick = { vm.update { copy(mode = ProxyMode.VPN) } },
            label = { Text("VPN") },
        )
        IconButton(onClick = onCompareModes) {
            Icon(Icons.Default.Info, contentDescription = "Comparer les modes")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FilePickerRow(label: String, fileName: String?, onPick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = fileName ?: "Aucun fichier",
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
