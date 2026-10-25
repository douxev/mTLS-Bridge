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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.douxev.mtls_bridge.R

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
                title = { Text(stringResource(R.string.help_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.common_back))
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
            item { Android17Card() }
            item { ImportBundleCard() }
            item { AdminBundleCard(onCopy = { copyToClipboard(context, it) }) }
            item { SecurityCard() }
        }
    }
}

@Composable
private fun OverviewCard() = SectionCard(title = stringResource(R.string.help_overview_title)) {
    Text(
        stringResource(R.string.help_overview_text),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.help_overview_key),
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun ModeCard(onCompareModes: () -> Unit) = SectionCard(title = stringResource(R.string.help_mode_title)) {
    Text(
        stringResource(R.string.help_mode_text),
        style = MaterialTheme.typography.bodyMedium,
    )
    AssistChip(
        onClick = onCompareModes,
        label = { Text(stringResource(R.string.help_compare_details)) },
        colors = AssistChipDefaults.assistChipColors(),
    )
}

@Composable
private fun Android17Card() = SectionCard(title = stringResource(R.string.help_android17_title)) {
    Text(
        stringResource(R.string.help_android17_profiles),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.help_android17_local_network),
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun ImportBundleCard() = SectionCard(title = stringResource(R.string.help_import_title)) {
    Text(
        stringResource(R.string.help_import_intro),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.help_import_steps),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.help_import_tip, stringResource(R.string.list_menu_delete_after_import)),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun AdminBundleCard(onCopy: (String) -> Unit) = SectionCard(
    title = stringResource(R.string.help_admin_title),
) {
    Text(
        stringResource(R.string.help_admin_text),
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
                    Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.help_copy_script))
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
        stringResource(R.string.help_admin_footer),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun SecurityCard() = SectionCard(title = stringResource(R.string.help_security_title)) {
    Text(
        stringResource(R.string.help_security_key),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.help_security_configs),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.help_security_isolation),
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        stringResource(R.string.help_security_audit),
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
        Toast.makeText(context, context.getString(R.string.help_script_copied), Toast.LENGTH_SHORT).show()
    }
}
