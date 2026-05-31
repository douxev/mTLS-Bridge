package com.douxev.mtls_bridge.ui.compare

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

private data class CompareRow(
    val criterion: String,
    val loopback: String,
    val vpn: String,
    val loopbackWins: Boolean,
)

private val rows = listOf(
    CompareRow(
        criterion = "Isolation entre apps",
        loopback = "Forte — un service par config, UID check strict (fail-closed)",
        vpn = "Faible — apps partagent le tun, UID check ne fonctionne pas pour les sockets virtuels",
        loopbackWins = true,
    ),
    CompareRow(
        criterion = "Consommation batterie au repos",
        loopback = "≈ 0 — listener dort sur epoll, démarre à la demande",
        vpn = "Modérée — service permanent, smoltcp parse tout le trafic des apps autorisées",
        loopbackWins = true,
    ),
    CompareRow(
        criterion = "Compatibilité avec une autre VPN",
        loopback = "Oui (WireGuard, Mullvad, etc. fonctionnent en parallèle)",
        vpn = "Non — l'OS n'autorise qu'une VPN active",
        loopbackWins = true,
    ),
    CompareRow(
        criterion = "Casse les autres connexions réseau de l'app",
        loopback = "Non — on n'intercept que les requêtes vers 127.0.0.1:PORT",
        vpn = "Oui — tout le trafic de l'app passe par le tun, les requêtes vers ses CDN/analytics tombent",
        loopbackWins = true,
    ),
    CompareRow(
        criterion = "URL à configurer dans l'app cliente",
        loopback = "http://127.0.0.1:PORT",
        vpn = "http://192.0.2.X:PORT (IP synthétique)",
        loopbackWins = false, // équivalent
    ),
    CompareRow(
        criterion = "Activation",
        loopback = "Toggle on/off par config — reste actif tant que enabled",
        vpn = "Toggle global VPN — toutes les configs VPN en même temps",
        loopbackWins = false,
    ),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CompareModesScreen(onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Loopback vs VPN") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Retour")
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { IntroCard() }
            items(rows) { row -> RowCard(row) }
            item { ConclusionCard() }
        }
    }
}

@Composable
private fun IntroCard() {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                "Pourquoi loopback par défaut ?",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                "Les deux modes demandent de retaper une URL personnalisée dans " +
                    "l'app cible (Jellyfin, Nextcloud…). À fonctionnalité équivalente, " +
                    "le mode loopback gagne sur la sécurité et l'énergie. " +
                    "Le mode VPN n'est utile que pour une app qui refuserait explicitement " +
                    "une URL en 127.0.0.1.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun RowCard(row: CompareRow) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                row.criterion,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            ModeLine(
                label = "Loopback",
                description = row.loopback,
                highlighted = row.loopbackWins,
            )
            HorizontalDivider()
            ModeLine(
                label = "VPN",
                description = row.vpn,
                highlighted = false,
            )
        }
    }
}

@Composable
private fun ModeLine(label: String, description: String, highlighted: Boolean) {
    Row(verticalAlignment = Alignment.Top) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = if (highlighted)
                MaterialTheme.colorScheme.tertiary
            else MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(96.dp),
        )
        Text(
            text = description,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun ConclusionCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                "Recommandation",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                "Utilise le loopback (par défaut). Bascule en VPN uniquement si " +
                    "l'app cible refuse une URL en localhost — c'est rare en pratique.",
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
