package com.douxev.mtls_bridge

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import com.douxev.mtls_bridge.ui.navigation.MtlsNavigation
import com.douxev.mtls_bridge.ui.theme.MtlswrapTheme
import com.douxev.mtls_bridge.ui.tv.LocalIsTv
import com.douxev.mtls_bridge.ui.tv.TvSafeArea
import com.douxev.mtls_bridge.ui.tv.isTelevision

class MainActivity : ComponentActivity() {

    // API 33+: without this permission the foreground service's persistent
    // notification is silently dropped, so the user cannot see that the
    // proxies are running nor reach the notification's "Stop" button.
    private val requestNotifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Result ignored: the user may refuse, the app keeps working without notifications. */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        (application as MtlsApplication).startLoopbackCoordinator()
        ensureNotificationPermission()
        enableEdgeToEdge()
        val isTv = isTelevision()
        setContent {
            // Android TV: dark theme (TV guideline) and safe-area margins
            // against television overscan.
            MtlswrapTheme(darkTheme = isTv || isSystemInDarkTheme()) {
                CompositionLocalProvider(LocalIsTv provides isTv) {
                    // Edge-to-edge is mandatory with targetSdk 36: Scaffolds handle the
                    // system bars and keyboard, but not a side display cutout in landscape.
                    Box(
                        Modifier
                            .fillMaxSize()
                            .background(MaterialTheme.colorScheme.background)
                            .windowInsetsPadding(
                                WindowInsets.displayCutout.only(WindowInsetsSides.Horizontal)
                            )
                            .then(if (isTv) Modifier.padding(TvSafeArea) else Modifier)
                    ) {
                        MtlsNavigation()
                    }
                }
            }
        }
    }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            requestNotifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
