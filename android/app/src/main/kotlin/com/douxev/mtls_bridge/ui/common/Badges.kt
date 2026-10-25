package com.douxev.mtls_bridge.ui.common

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.data.KeySecurityLevel
import com.douxev.mtls_bridge.data.ProxyMode

@Composable
fun SecurityBadge(level: KeySecurityLevel, modifier: Modifier = Modifier) {
    val (label, container, on) = when (level) {
        KeySecurityLevel.STRONGBOX -> Triple(
            "StrongBox",
            MaterialTheme.colorScheme.tertiaryContainer,
            MaterialTheme.colorScheme.onTertiaryContainer,
        )
        KeySecurityLevel.TRUSTED_ENVIRONMENT -> Triple(
            "TEE",
            MaterialTheme.colorScheme.secondaryContainer,
            MaterialTheme.colorScheme.onSecondaryContainer,
        )
        KeySecurityLevel.SOFTWARE -> Triple(
            stringResource(R.string.common_badge_software),
            MaterialTheme.colorScheme.errorContainer,
            MaterialTheme.colorScheme.onErrorContainer,
        )
        KeySecurityLevel.UNKNOWN -> Triple(
            stringResource(R.string.common_badge_unknown),
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(50),
        color = container,
    ) {
        Text(
            text = label,
            color = on,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
}

@Composable
fun ModeChip(mode: ProxyMode) {
    AssistChip(
        onClick = {},
        label = {
            Text(
                stringResource(
                    if (mode == ProxyMode.VPN) R.string.common_mode_vpn else R.string.common_mode_loopback
                )
            )
        },
        colors = AssistChipDefaults.assistChipColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    )
}

@Composable
fun BadgeRow(level: KeySecurityLevel, mode: ProxyMode) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        SecurityBadge(level)
        ModeChip(mode)
    }
}
