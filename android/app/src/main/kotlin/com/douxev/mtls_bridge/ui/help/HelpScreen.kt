package com.douxev.mtls_bridge.ui.help

import android.content.ClipData
import android.content.ClipboardManager
import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HelpScreen(
    onBack: () -> Unit,
    onCompareModes: () -> Unit,
) {
    val context = LocalContext.current
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Aide & déploiement") },
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
            item { OverviewCard() }
            item { ModeCard(onCompareModes) }
            item { ImportBundleCard() }
            item { AdminBundleCard(onCopy = { copyToClipboard(context, it) }) }
            item { SecurityCard() }
        }
    }
}

@Composable
private fun OverviewCard() = SectionCard(title = "Qu'est-ce que mTLS Bridge ?") {
    Text(
        "mTLS Bridge est un proxy local mTLS pour Android. Tu pointes ton app " +
            "(Jellyfin, Nextcloud, Home Assistant…) vers une URL en localhost ; " +
            "mTLS Bridge intercepte la requête en clair, la chiffre avec ton " +
            "certificat client, et la relaie vers ton backend self-hosted.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        "La clé privée reste dans Android Keystore (TEE matériel quand " +
            "disponible), non-exportable du device.",
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun ModeCard(onCompareModes: () -> Unit) = SectionCard(title = "Loopback vs VPN") {
    Text(
        "Deux modes existent. Le loopback (recommandé) est plus sûr et plus " +
            "économe en batterie : chaque config a son port 127.0.0.1, isolation " +
            "stricte par UID, démarrage on-demand. Le VPN n'est utile que pour " +
            "les apps qui refusent une URL en localhost.",
        style = MaterialTheme.typography.bodyMedium,
    )
    AssistChip(
        onClick = onCompareModes,
        label = { Text("Comparer en détail") },
        colors = AssistChipDefaults.assistChipColors(),
    )
}

@Composable
private fun ImportBundleCard() = SectionCard(title = "Importer un bundle de déploiement") {
    Text(
        "Si ton admin t'a envoyé un fichier .zip mtls-bridge-bundle :",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        "1. Menu ⋮ en haut de la liste → Importer\n" +
            "2. Sélectionne le .zip\n" +
            "3. Saisis la passphrase (transmise séparément par ton admin)\n" +
            "4. Toutes les configs apparaissent, déjà actives\n" +
            "5. Ouvre ton app (ex. Jellyfin), tape l'URL affichée sur la " +
            "card de la config",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        "Optionnel : coche \"Supprimer le fichier après import\" pour ne pas " +
            "laisser traîner le bundle sur ton filesystem.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun AdminBundleCard(onCopy: (String) -> Unit) = SectionCard(
    title = "Générer un bundle (admin IT)",
) {
    Text(
        "Pour distribuer mTLS Bridge à des employés sans qu'ils touchent à " +
            "openssl : ce script bash génère un .zip prêt à l'import. " +
            "L'employé n'a qu'à cliquer dessus.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "bundle-generator.sh",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                IconButton(onClick = { onCopy(DEPLOYMENT_SCRIPT_BASH) }) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copier")
                }
            }
            Text(
                DEPLOYMENT_SCRIPT_BASH,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
    Text(
        "Adapte les variables en haut du script (config_id, hôte, CA…). " +
            "La passphrase aléatoire est imprimée à la fin — transmets-la à " +
            "l'employé par un canal séparé (Signal, Matrix, SMS).",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun SecurityCard() = SectionCard(title = "Sécurité — résumé") {
    Text(
        "• Clé privée : dans Android Keystore (TEE / StrongBox), " +
            "non-exportable du device. L'UI affiche le niveau effectivement " +
            "obtenu (StrongBox / TEE / Software).",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        "• Configs : stockées chiffrées (SQLCipher AES-256-GCM, passphrase " +
            "wrappée par un master-key AES Keystore).",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        "• Isolation : chaque proxy loopback a son UID check fail-closed via " +
            "ConnectivityManager.getConnectionOwnerUid — aucune autre app ne " +
            "peut intercepter la session.",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        "• Audit : tous les événements (bind, accept, reject, bridge, …) " +
            "sont persistés en DB chiffrée et consultables par config. Purge " +
            "automatique au-delà de 7 jours.",
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun SectionCard(
    title: String,
    content: @Composable () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            content()
        }
    }
}

private fun copyToClipboard(context: android.content.Context, text: String) {
    val mgr = context.getSystemService(ClipboardManager::class.java)
    mgr.setPrimaryClip(ClipData.newPlainText("mTLS Bridge deployment script", text))
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
        Toast.makeText(context, "Script copié", Toast.LENGTH_SHORT).show()
    }
}
