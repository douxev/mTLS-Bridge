package com.douxev.mtls_bridge.ui.list

import android.app.Activity
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.runtime.SafFileUtils
import com.douxev.mtls_bridge.service.ProxyLauncher
import com.douxev.mtls_bridge.ui.common.BadgeRow
import com.douxev.mtls_bridge.ui.common.launchOrExplain
import com.douxev.mtls_bridge.ui.common.rememberLocalNetworkGate
import com.douxev.mtls_bridge.ui.tv.LocalIsTv
import com.douxev.mtls_bridge.ui.tv.tvFocusHighlight
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfigListScreen(
    onAddClick: () -> Unit,
    onConfigClick: (id: String) -> Unit,
    onEditClick: (id: String) -> Unit,
    onHelpClick: () -> Unit,
    onRemoteClick: () -> Unit,
    vm: ConfigListViewModel = viewModel(factory = ConfigListViewModel.Factory),
) {
    val configs by vm.configs.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val app = context.applicationContext as MtlsApplication
    val vpnRunning by app.vpnRunning.collectAsStateWithLifecycle()
    val hasVpnConfigs = configs.any { it.mode == ProxyMode.VPN }
    val localNetworkGate = rememberLocalNetworkGate()
    val isTv = LocalIsTv.current

    // Proxies démarrés sans geste ici (ouverture de l'app, import de bundle) :
    // permission réseau local (Android 17) demandée une fois s'il le faut.
    val activeUpstreams = configs
        .filter { (it.mode == ProxyMode.LOOPBACK && it.enabled) || (it.mode == ProxyMode.VPN && vpnRunning) }
        .map { it.upstreamHost }
        .distinct()
    LaunchedEffect(activeUpstreams) { localNetworkGate.checkQuietly(activeUpstreams) }

    val vpnPrep = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            ProxyLauncher.startVpnGlobal(context)
        }
    }

    val scope = rememberCoroutineScope()
    var showExportDialog by remember { mutableStateOf(false) }
    var pendingExportIds by remember { mutableStateOf<Set<String>?>(null) }
    var deleteImportFile by remember { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<ConfigEntity?>(null) }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri ->
        // Capturer la sélection AVANT de la remettre à null : la coroutine
        // s'exécute après ce callback et lirait sinon null (= tout exporter).
        val ids = pendingExportIds
        pendingExportIds = null
        if (uri == null) return@rememberLauncherForActivityResult
        if (ids == null) {
            // Sélection perdue (process tué pendant le sélecteur de fichier) :
            // on n'exporte surtout pas tout par défaut.
            Toast.makeText(context, "Sélection perdue, relance l'export", Toast.LENGTH_LONG).show()
            return@rememberLauncherForActivityResult
        }
        scope.launch {
            try {
                val bytes = vm.exportToZip(ids)
                SafFileUtils.writeBytes(context, uri, bytes)
                Toast.makeText(context, "${bytes.size / 1024} ko exportés", Toast.LENGTH_SHORT).show()
            } catch (t: Throwable) {
                Toast.makeText(context, "Export échoué : ${t.message}", Toast.LENGTH_LONG).show()
            }
        }
    }
    var importPassphrasePending by remember {
        mutableStateOf<Pair<android.net.Uri, ByteArray>?>(null)
    }
    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        if (uri != null) scope.launch {
            try {
                val bytes = SafFileUtils.readBytes(context, uri)
                val preview = vm.peekImportZip(bytes)
                if (preview.needsPassphrase) {
                    // Deployment bundle : on demande la passphrase commune des .p12.
                    importPassphrasePending = uri to bytes
                } else {
                    val r = vm.importFromZip(bytes)
                    Toast.makeText(
                        context,
                        "${r.importedWithoutKey} sans clé, ${r.skipped} ignorée(s). " +
                            "Rajoute les .p12 dans le détail de chaque config.",
                        Toast.LENGTH_LONG,
                    ).show()
                    if (deleteImportFile) SafFileUtils.deleteIfPossible(context, uri)
                }
            } catch (t: Throwable) {
                Toast.makeText(context, "Import échoué : ${t.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    importPassphrasePending?.let { (uri, bytes) ->
        BundlePassphraseDialog(
            onConfirm = { passphrase ->
                scope.launch {
                    try {
                        val r = vm.importFromZip(bytes, passphrase.toCharArray())
                        Toast.makeText(
                            context,
                            "${r.importedWithKey} prête(s) à l'emploi, " +
                                "${r.importedWithoutKey} sans clé, ${r.skipped} ignorée(s).",
                            Toast.LENGTH_LONG,
                        ).show()
                        if (deleteImportFile) SafFileUtils.deleteIfPossible(context, uri)
                    } catch (t: Throwable) {
                        Toast.makeText(context, "Import échoué : ${t.message}", Toast.LENGTH_LONG).show()
                    }
                }
                importPassphrasePending = null
            },
            onDismiss = { importPassphrasePending = null },
        )
    }

    pendingDelete?.let { cfg ->
        DeleteConfirmDialog(
            config = cfg,
            onConfirm = {
                vm.delete(cfg.id)
                pendingDelete = null
            },
            onDismiss = { pendingDelete = null },
        )
    }

    if (showExportDialog) {
        ExportSelectionDialog(
            configs = configs,
            onConfirm = { selected ->
                showExportDialog = false
                pendingExportIds = selected
                exportLauncher.launchOrExplain(context, "mtls_bridge-backup.zip")
            },
            onDismiss = { showExportDialog = false },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Configurations mTLS") },
                actions = {
                    var menuOpen by remember { mutableStateOf(false) }
                    IconButton(onClick = { menuOpen = true }) {
                        Icon(Icons.Default.MoreVert, contentDescription = "Plus")
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text("Exporter…") },
                            onClick = {
                                menuOpen = false
                                showExportDialog = true
                            },
                            enabled = configs.isNotEmpty(),
                        )
                        DropdownMenuItem(
                            text = { Text("Importer…") },
                            onClick = {
                                menuOpen = false
                                importLauncher.launchOrExplain(context, "application/zip")
                            },
                        )
                        DropdownMenuItem(
                            text = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Checkbox(
                                        checked = deleteImportFile,
                                        onCheckedChange = { deleteImportFile = it },
                                    )
                                    Text("Supprimer le fichier après import")
                                }
                            },
                            onClick = { deleteImportFile = !deleteImportFile },
                        )
                        DropdownMenuItem(
                            text = { Text("Configuration à distance…") },
                            onClick = {
                                menuOpen = false
                                onRemoteClick()
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Aide & déploiement") },
                            onClick = {
                                menuOpen = false
                                onHelpClick()
                            },
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onAddClick,
                icon = { Icon(Icons.Default.Add, contentDescription = null) },
                text = { Text("Nouvelle config") },
            )
        },
    ) { padding ->
        if (configs.isEmpty()) {
            EmptyState(padding, onRemoteClick)
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                // Marge basse : la dernière carte ne doit pas finir sous le FAB.
                contentPadding = PaddingValues(start = 16.dp, top = 16.dp, end = 16.dp, bottom = 96.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                // Sur TV, saisir hôte, .p12 et passphrase à la télécommande est
                // pénible : la console web est mise en avant.
                if (isTv) {
                    item { RemoteConfigCard(onRemoteClick) }
                }
                if (hasVpnConfigs) {
                    item {
                        VpnGlobalToggle(
                            running = vpnRunning,
                            onToggle = {
                                if (vpnRunning) {
                                    ProxyLauncher.stopVpn(context)
                                } else {
                                    val vpnHosts = configs
                                        .filter { it.mode == ProxyMode.VPN }
                                        .map { it.upstreamHost }
                                    localNetworkGate.runAfterCheck(vpnHosts) {
                                        val prep = ProxyLauncher.vpnPrepareIntentIfNeeded(context)
                                        if (prep != null) vpnPrep.launch(prep)
                                        else ProxyLauncher.startVpnGlobal(context)
                                    }
                                }
                            },
                            configCount = configs.count { it.mode == ProxyMode.VPN },
                        )
                    }
                }
                items(configs, key = { it.id }) { cfg ->
                    ConfigCard(
                        config = cfg,
                        onClick = { onConfigClick(cfg.id) },
                        onEdit = { onEditClick(cfg.id) },
                        onDelete = { pendingDelete = cfg },
                        onToggleEnabled = { enabled ->
                            if (enabled) {
                                localNetworkGate.runAfterCheck(listOf(cfg.upstreamHost)) {
                                    vm.setEnabled(cfg.id, true)
                                }
                            } else {
                                vm.setEnabled(cfg.id, false)
                            }
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun VpnGlobalToggle(running: Boolean, onToggle: () -> Unit, configCount: Int) {
    Card(
        modifier = Modifier.fillMaxWidth().tvFocusHighlight(),
        colors = androidx.compose.material3.CardDefaults.cardColors(
            containerColor = if (running)
                MaterialTheme.colorScheme.tertiaryContainer
            else MaterialTheme.colorScheme.surfaceVariant,
        ),
        elevation = androidx.compose.material3.CardDefaults.cardElevation(defaultElevation = 2.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    if (running) "Tunnel VPN actif" else "Tunnel VPN arrêté",
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    "$configCount config(s) en mode VPN",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = running, onCheckedChange = { onToggle() })
        }
    }
}

@Composable
private fun BundlePassphraseDialog(
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var pw by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Passphrase du bundle") },
        text = {
            Column {
                Text(
                    "Ce bundle contient des .p12 chiffrés. Saisis la passphrase " +
                        "commune (fournie par ton admin) pour déchiffrer toutes les " +
                        "clés en une fois.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                OutlinedTextField(
                    value = pw,
                    onValueChange = { pw = it },
                    label = { Text("Passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(pw); pw = "" }, enabled = pw.isNotEmpty()) {
                Text("Importer")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Annuler") } },
    )
}

@Composable
private fun DeleteConfirmDialog(
    config: ConfigEntity,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Supprimer « ${config.displayName} » ?") },
        text = {
            Text(
                "La clé privée est effacée du Keystore et ne peut pas être " +
                    "récupérée : il faudra ré-importer le .p12 d'origine pour " +
                    "recréer cette config.",
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text("Supprimer", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Annuler") } },
    )
}

@Composable
private fun ExportSelectionDialog(
    configs: List<ConfigEntity>,
    onConfirm: (Set<String>) -> Unit,
    onDismiss: () -> Unit,
) {
    val selected = remember { mutableStateOf(configs.map { it.id }.toSet()) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Exporter les configs") },
        text = {
            Column {
                Text(
                    "Coche les configs à inclure dans le zip. " +
                        "Le fichier contient les certs publics + métadonnées, " +
                        "pas la clé privée (qui reste dans le Keystore).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                Row {
                    TextButton(onClick = {
                        selected.value = configs.map { it.id }.toSet()
                    }) { Text("Tout") }
                    TextButton(onClick = { selected.value = emptySet() }) { Text("Aucun") }
                }
                LazyColumn(modifier = Modifier.padding(top = 4.dp)) {
                    items(configs, key = { it.id }) { c ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(
                                checked = c.id in selected.value,
                                onCheckedChange = { checked ->
                                    selected.value = if (checked)
                                        selected.value + c.id
                                    else selected.value - c.id
                                },
                            )
                            Text(c.displayName)
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(selected.value) },
                enabled = selected.value.isNotEmpty(),
            ) { Text("Exporter") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Annuler") }
        },
    )
}

@Composable
private fun EmptyState(padding: PaddingValues, onRemoteClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            "Aucune configuration mTLS",
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            "Importe un .p12 pour wrapper une app avec mTLS.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.padding(top = 16.dp))
        OutlinedButton(
            onClick = onRemoteClick,
            modifier = Modifier.tvFocusHighlight(ButtonDefaults.outlinedShape),
        ) {
            Text("Configurer depuis un ordinateur ou un smartphone")
        }
    }
}

@Composable
private fun RemoteConfigCard(onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().tvFocusHighlight(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Configuration à distance", style = MaterialTheme.typography.titleMedium)
            Text(
                "Ouvre une page web sur le réseau local pour créer et modifier les " +
                    "configs depuis le navigateur d'un ordinateur ou d'un smartphone.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun ConfigCard(
    config: ConfigEntity,
    onClick: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onToggleEnabled: (Boolean) -> Unit,
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().tvFocusHighlight(),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        config.displayName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "${config.upstreamHost}:${config.upstreamPort}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        config.targetPackage.ifBlank { "⚠ aucune app cible — modifier" },
                        style = MaterialTheme.typography.bodySmall,
                        color = if (config.targetPackage.isBlank())
                            MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (config.needsKeystoreRefresh) {
                        Text(
                            "⚠ clé manquante — re-importer le .p12 (détail)",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // Switch on/off pour les loopbacks. Pour les VPN, le contrôle
                    // se fait via le toggle global (en haut de la liste).
                    // Désactivé si la clé Keystore manque (import depuis fichier).
                    if (config.mode == ProxyMode.LOOPBACK) {
                        Switch(
                            checked = config.enabled,
                            onCheckedChange = onToggleEnabled,
                            enabled = !config.needsKeystoreRefresh,
                            modifier = Modifier.padding(end = 4.dp),
                        )
                    }
                    IconButton(onClick = onEdit) {
                        Icon(Icons.Default.Edit, contentDescription = "Modifier")
                    }
                    IconButton(onClick = onDelete) {
                        Icon(Icons.Outlined.Delete, contentDescription = "Supprimer")
                    }
                }
            }
            Spacer(Modifier.padding(top = 8.dp))
            BadgeRow(level = config.securityLevel, mode = config.mode)
        }
    }
}
