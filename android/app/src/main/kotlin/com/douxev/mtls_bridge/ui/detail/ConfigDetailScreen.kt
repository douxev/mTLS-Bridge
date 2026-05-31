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
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.data.AuditEventEntity
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.runtime.SafFileUtils
import com.douxev.mtls_bridge.service.ProxyLauncher
import com.douxev.mtls_bridge.ui.common.BadgeRow
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
                title = { Text(config?.displayName ?: "Config") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Retour")
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
                    .padding(padding),
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
                        "Événements récents",
                        style = MaterialTheme.typography.titleSmall,
                    )
                }
                if (events.isEmpty()) {
                    item {
                        Text(
                            "Aucun événement.",
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
        Text("Chargement…")
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
                "Upstream : ${cfg.upstreamHost}:${cfg.upstreamPort}",
                style = MaterialTheme.typography.bodyMedium,
            )
            cfg.sni?.let {
                Text("SNI : $it", style = MaterialTheme.typography.bodySmall)
            }
            ClientUrlRow(cfg = cfg, onCopy = { url -> copyToClipboard(context, url) })
            androidx.compose.foundation.layout.Spacer(Modifier.padding(top = 4.dp))
            BadgeRow(level = cfg.securityLevel, mode = cfg.mode)
        }
    }
}

@Composable
private fun ClientUrlRow(cfg: ConfigEntity, onCopy: (String) -> Unit) {
    val url: String? = when (cfg.mode) {
        ProxyMode.VPN -> if (!cfg.syntheticIp.isNullOrBlank() && cfg.syntheticPort != null)
            "http://${cfg.syntheticIp}:${cfg.syntheticPort}"
        else null
        ProxyMode.LOOPBACK -> {
            // Port 0 = éphémère, on ne connaît pas le port avant que le service
            // bind. La doxev verra le port réel dans les events BIND_OK.
            val p = cfg.loopbackPort
            if (p != null && p > 0) "http://127.0.0.1:$p" else null
        }
    }
    androidx.compose.foundation.layout.Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "URL à configurer dans l'app cible :",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                url ?: "— port éphémère, voir BIND_OK dans les events",
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
            )
        }
        if (url != null) {
            IconButton(onClick = { onCopy(url) }) {
                Icon(Icons.Default.ContentCopy, contentDescription = "Copier l'URL")
            }
        }
    }
}

private fun copyToClipboard(context: Context, text: String) {
    val mgr = context.getSystemService(ClipboardManager::class.java)
    mgr.setPrimaryClip(ClipData.newPlainText("mTLS Bridge URL", text))
    // Sur Android 13+ l'OS affiche son propre toast système, on n'en ajoute pas.
    if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) {
        Toast.makeText(context, "Copié : $text", Toast.LENGTH_SHORT).show()
    }
}

@Composable
private fun LaunchControls(cfg: ConfigEntity) {
    val context = LocalContext.current
    val activity = context as? Activity
    when (cfg.mode) {
        ProxyMode.VPN -> {
            // En VPN, le tunnel est piloté globalement depuis la liste (toggle
            // dans l'AppBar). Ici on offre juste un raccourci pour ouvrir l'app
            // cible une fois le tunnel actif.
            Button(
                onClick = {
                    activity?.let { ProxyLauncher.launchTargetApp(it, cfg.targetPackage) }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = cfg.targetPackage.isNotBlank(),
            ) {
                Text(
                    if (cfg.targetPackage.isBlank()) "Aucune app cible — modifier la config"
                    else "Ouvrir l'app"
                )
            }
        }
        ProxyMode.LOOPBACK -> {
            // Le proxy loopback tourne en permanence quand la config est
            // `enabled` — pilotage via le Switch de la card dans la liste.
            // Ici on offre juste un raccourci pour ouvrir l'app cible.
            Button(
                onClick = {
                    activity?.let { ProxyLauncher.launchTargetApp(it, cfg.targetPackage) }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = cfg.targetPackage.isNotBlank() && cfg.enabled,
            ) {
                Text(
                    when {
                        cfg.targetPackage.isBlank() -> "Aucune app cible — modifier la config"
                        !cfg.enabled -> "Config désactivée — réactive avec le Switch"
                        else -> "Ouvrir l'app"
                    }
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
                "Clé Keystore manquante",
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                "Cette config a été importée depuis un fichier. Re-fournis ton " +
                    ".p12 (et sa passphrase) pour activer le proxy. Le cert et la " +
                    "passphrase ne quittent jamais le device.",
                style = MaterialTheme.typography.bodyMedium,
            )
            androidx.compose.foundation.layout.Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
            ) {
                Button(onClick = { pickP12.launch("*/*") }) { Text("Choisir .p12") }
                Text(
                    p12Uri?.lastPathSegment ?: "aucun fichier",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text("Passphrase du .p12") },
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
                    "Supprimer le .p12 du filesystem après import",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(
                onClick = {
                    val uri = p12Uri ?: return@Button
                    busy = true; error = null
                    scope.launch {
                        val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                            ?: run { busy = false; error = "lecture .p12 impossible"; return@launch }
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
            ) { Text(if (busy) "Import…" else "Importer la clé") }
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

