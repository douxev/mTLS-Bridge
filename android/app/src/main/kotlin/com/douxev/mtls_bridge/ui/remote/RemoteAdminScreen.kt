package com.douxev.mtls_bridge.ui.remote

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
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.douxev.mtls_bridge.remote.RemoteAdminServer
import com.douxev.mtls_bridge.ui.tv.tvFocusHighlight

/**
 * Écran « Configuration à distance » : affiche l'adresse HTTPS de la console,
 * un QR code et le PIN d'appairage. Tant qu'il est ouvert, l'écran reste
 * allumé (sinon l'écran de veille d'Android TV le masquerait au milieu de la
 * saisie sur l'ordinateur).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RemoteAdminScreen(
    onBack: () -> Unit,
    vm: RemoteAdminViewModel = viewModel(factory = RemoteAdminViewModel.Factory),
) {
    val status by vm.status.collectAsStateWithLifecycle()

    val view = LocalView.current
    DisposableEffect(view) {
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = false }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Configuration à distance") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Retour")
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
                ) { Details(status, vm) }
                status.qrPayload?.takeIf { status.running }?.let { qr ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        QrCode(qr, size = 240.dp)
                        Text(
                            "Scanne avec le téléphone",
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
                Details(status, vm)
                status.qrPayload?.takeIf { status.running }?.let { qr ->
                    QrCode(qr, size = 200.dp, modifier = Modifier.align(Alignment.CenterHorizontally))
                }
            }
        }
    }
}

@Composable
private fun ColumnScope.Details(status: RemoteAdminServer.Status, vm: RemoteAdminViewModel) {
    Text(
        "Ouvre l'adresse ci-dessous dans le navigateur d'un ordinateur ou d'un " +
            "smartphone connecté au même réseau, puis saisis le PIN. Tu pourras y " +
            "créer, modifier et activer les configs, déposer le .p12, la CA ou un " +
            "bundle de déploiement.",
        style = MaterialTheme.typography.bodyLarge,
    )

    when {
        status.starting -> Text("Démarrage…", style = MaterialTheme.typography.bodyLarge)
        !status.running -> {
            Text(
                status.error ?: "Console arrêtée.",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyLarge,
            )
            Button(onClick = vm::restart, modifier = Modifier.tvFocusHighlight(ButtonDefaults.shape)) {
                Text("Relancer la console")
            }
        }
        else -> {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("Adresse", style = MaterialTheme.typography.labelLarge)
                    if (status.urls.isEmpty()) {
                        Text(
                            "Aucune adresse réseau locale : connecte l'appareil au Wi-Fi ou à l'Ethernet.",
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
                    Text("PIN d'appairage", style = MaterialTheme.typography.labelLarge)
                    Text(
                        status.pin.chunked(3).joinToString(" "),
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        fontSize = 44.sp,
                        letterSpacing = 4.sp,
                    )
                    Text(
                        "Usage unique : un nouveau PIN s'affiche après chaque appairage.",
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
                    Text("Avertissement du navigateur", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "La console utilise un certificat généré sur cet appareil : le " +
                            "navigateur signale une connexion « non privée ». Vérifie que " +
                            "l'empreinte SHA-256 affichée par le navigateur commence comme " +
                            "celle-ci avant de continuer :",
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
                when (status.sessions) {
                    0 -> "Aucun navigateur connecté."
                    1 -> "1 navigateur connecté."
                    else -> "${status.sessions} navigateurs connectés."
                },
                style = MaterialTheme.typography.bodyLarge,
            )
            status.lastActivity?.let {
                Text("Dernière action : $it", style = MaterialTheme.typography.bodyMedium)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(
                    onClick = vm::disconnectAll,
                    enabled = status.sessions > 0,
                    modifier = Modifier.tvFocusHighlight(ButtonDefaults.outlinedShape),
                ) { Text("Déconnecter les navigateurs") }
            }
            Text(
                "La console s'arrête quand tu quittes cet écran, ou après 15 min sans activité.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
