package com.douxev.mtls_bridge.ui.tv

import android.app.UiModeManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.dp

/** Android TV / Google TV (mode TV ou feature leanback). */
fun Context.isTelevision(): Boolean {
    val uiMode = getSystemService(UiModeManager::class.java)?.currentModeType
    return uiMode == Configuration.UI_MODE_TYPE_TELEVISION ||
        packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)
}

/** Fourni une fois par [com.douxev.mtls_bridge.MainActivity]. */
val LocalIsTv = staticCompositionLocalOf { false }

/** Marges de sécurité recommandées pour les téléviseurs (zone d'overscan). */
val TvSafeArea = PaddingValues(horizontal = 48.dp, vertical = 27.dp)

/**
 * Contour bien visible à 3 m quand l'élément (ou l'un de ses enfants) a le
 * focus D-pad. L'état « focused » natif de Material3 (voile à ~10 %) se voit
 * mal sur une TV. No-op hors TV.
 */
@Composable
fun Modifier.tvFocusHighlight(shape: Shape = CardDefaults.shape): Modifier {
    if (!LocalIsTv.current) return this
    var focused by remember { mutableStateOf(false) }
    val color = MaterialTheme.colorScheme.primary
    return this
        .onFocusChanged { focused = it.hasFocus }
        .border(width = 3.dp, color = if (focused) color else Color.Transparent, shape = shape)
}
