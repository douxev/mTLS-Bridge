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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
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
                title = { Text("Modifier la config") },
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
                // Edge-to-edge : réserve la hauteur du clavier (cf. AddConfigScreen).
                .consumeWindowInsets(padding)
                .imePadding()
                .padding(horizontal = 16.dp, vertical = 12.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Le certificat et la clé Keystore ne sont pas modifiables ici. " +
                    "Pour faire tourner les certs, supprime puis recrée la config.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = state.displayName,
                onValueChange = { v -> vm.update { copy(displayName = v) } },
                label = { Text("Nom") },
                singleLine = true,
                enabled = state.loaded,
                modifier = Modifier.fillMaxWidth(),
            )

            AppPicker(state, vm)

            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = state.upstreamHost,
                    onValueChange = { v -> vm.update { copy(upstreamHost = v) } },
                    label = { Text("Hôte upstream") },
                    singleLine = true,
                    enabled = state.loaded,
                    modifier = Modifier.weight(2f),
                )
                OutlinedTextField(
                    value = state.upstreamPort,
                    onValueChange = { v ->
                        vm.update { copy(upstreamPort = v.filter { c -> c.isDigit() }) }
                    },
                    label = { Text("Port") },
                    singleLine = true,
                    enabled = state.loaded,
                    modifier = Modifier.weight(1f),
                )
            }

            OutlinedTextField(
                value = state.sni,
                onValueChange = { v -> vm.update { copy(sni = v) } },
                label = { Text("SNI (optionnel)") },
                singleLine = true,
                enabled = state.loaded,
                modifier = Modifier.fillMaxWidth(),
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = state.mode == ProxyMode.VPN,
                    onClick = { vm.update { copy(mode = ProxyMode.VPN) } },
                    label = { Text("VPN") },
                    enabled = state.loaded,
                )
                FilterChip(
                    selected = state.mode == ProxyMode.LOOPBACK,
                    onClick = { vm.update { copy(mode = ProxyMode.LOOPBACK) } },
                    label = { Text("Loopback") },
                    enabled = state.loaded,
                )
            }

            if (state.mode == ProxyMode.VPN) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.syntheticIp,
                        onValueChange = { v -> vm.update { copy(syntheticIp = v) } },
                        label = { Text("IP synthétique") },
                        singleLine = true,
                        enabled = state.loaded,
                        modifier = Modifier.weight(2f),
                    )
                    OutlinedTextField(
                        value = state.syntheticPort,
                        onValueChange = { v ->
                            vm.update { copy(syntheticPort = v.filter { c -> c.isDigit() }) }
                        },
                        label = { Text("Port") },
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
                    label = { Text("Port loopback (0 = éphémère)") },
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
                // L'hôte upstream peut changer : permission réseau local
                // (Android 17) avant que le coordinator ne relance le proxy.
                onClick = { localNetworkGate.runAfterCheck(listOf(state.upstreamHost)) { vm.submit() } },
                enabled = state.loaded && !state.submitting,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.submitting) "Sauvegarde…" else "Sauvegarder")
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
                ?: "Choisir l'app cible",
            onValueChange = {},
            label = { Text("App cliente") },
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
                        "Token d'isolation dans l'URL",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        "Recommandé : empêche les autres apps du téléphone d'utiliser " +
                            "votre certificat via le port loopback. Les webviews " +
                            "(Jellyfin Android, Nextcloud) fonctionnent grâce au cookie " +
                            "de session posé par la première page ouverte avec le token. " +
                            "Changer le token invalide l'URL configurée dans l'app cible — " +
                            "il faudra la recopier après sauvegarde.",
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
                    ) { Text("Régénérer") }
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
