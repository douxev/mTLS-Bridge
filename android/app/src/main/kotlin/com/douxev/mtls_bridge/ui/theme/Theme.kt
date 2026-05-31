package com.douxev.mtls_bridge.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

private val DarkColors = darkColorScheme(
    primary = LockBlue80,
    secondary = LockTeal80,
    tertiary = LockSand80,
)

private val LightColors = lightColorScheme(
    primary = LockBlue40,
    secondary = LockTeal40,
    tertiary = LockSand40,
)

@Composable
fun MtlswrapTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Dynamic color : palette dérivée du fond d'écran (Android 12+).
    // On l'active par défaut, c'est cohérent avec Material You / M3 Expressive.
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val ctx = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        }
        darkTheme -> DarkColors
        else -> LightColors
    }
    MaterialTheme(colorScheme = colorScheme, content = content)
}
