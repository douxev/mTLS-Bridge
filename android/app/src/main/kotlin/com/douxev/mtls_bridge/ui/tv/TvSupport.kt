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

/** Android TV / Google TV (TV UI mode or leanback feature). */
fun Context.isTelevision(): Boolean {
    val uiMode = getSystemService(UiModeManager::class.java)?.currentModeType
    return uiMode == Configuration.UI_MODE_TYPE_TELEVISION ||
        packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)
}

/** Provided once by [com.douxev.mtls_bridge.MainActivity]. */
val LocalIsTv = staticCompositionLocalOf { false }

/** Recommended safe-area margins for televisions (overscan area). */
val TvSafeArea = PaddingValues(horizontal = 48.dp, vertical = 27.dp)

/**
 * Outline clearly visible from 3 m away when the element (or one of its
 * children) has D-pad focus. Material3's native "focused" state (a ~10 %
 * overlay) is hard to see on a TV. No-op outside TV.
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
