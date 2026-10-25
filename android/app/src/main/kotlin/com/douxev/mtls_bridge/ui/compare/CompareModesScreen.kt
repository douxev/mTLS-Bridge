package com.douxev.mtls_bridge.ui.compare

import androidx.annotation.StringRes
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.douxev.mtls_bridge.R

private data class CompareRow(
    @StringRes val criterion: Int,
    @StringRes val loopback: Int,
    @StringRes val vpn: Int,
    val loopbackWins: Boolean,
)

private val rows = listOf(
    CompareRow(
        criterion = R.string.compare_isolation,
        loopback = R.string.compare_isolation_loopback,
        vpn = R.string.compare_isolation_vpn,
        loopbackWins = true,
    ),
    CompareRow(
        criterion = R.string.compare_battery,
        loopback = R.string.compare_battery_loopback,
        vpn = R.string.compare_battery_vpn,
        loopbackWins = true,
    ),
    CompareRow(
        criterion = R.string.compare_other_vpn,
        loopback = R.string.compare_other_vpn_loopback,
        vpn = R.string.compare_other_vpn_vpn,
        loopbackWins = true,
    ),
    CompareRow(
        criterion = R.string.compare_breaks_traffic,
        loopback = R.string.compare_breaks_traffic_loopback,
        vpn = R.string.compare_breaks_traffic_vpn,
        loopbackWins = true,
    ),
    CompareRow(
        criterion = R.string.compare_client_url,
        loopback = R.string.compare_client_url_loopback,
        vpn = R.string.compare_client_url_vpn,
        loopbackWins = false, // Equivalent.
    ),
    CompareRow(
        criterion = R.string.compare_activation,
        loopback = R.string.compare_activation_loopback,
        vpn = R.string.compare_activation_vpn,
        loopbackWins = false,
    ),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CompareModesScreen(onBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.compare_title)) },
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
                stringResource(R.string.compare_intro_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                stringResource(R.string.compare_intro_text),
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
                stringResource(row.criterion),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            ModeLine(
                label = stringResource(R.string.common_mode_loopback),
                description = stringResource(row.loopback),
                highlighted = row.loopbackWins,
            )
            HorizontalDivider()
            ModeLine(
                label = stringResource(R.string.common_mode_vpn),
                description = stringResource(row.vpn),
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
                stringResource(R.string.compare_conclusion_title),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                stringResource(R.string.compare_conclusion_text),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}
