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

    // API 33+ : sans cette permission, la notification persistante du
    // ForegroundService est silencieusement supprimée → la doxev ne voit
    // pas que les proxies tournent ni le bouton "Arrêter" de la notif.
    private val requestNotifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* result ignoré — l'utilisatrice peut refuser, on continue sans notif */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        (application as MtlsApplication).startLoopbackCoordinator()
        ensureNotificationPermission()
        enableEdgeToEdge()
        val isTv = isTelevision()
        setContent {
            // Android TV : thème sombre (recommandation TV) et marges de
            // sécurité contre l'overscan des téléviseurs.
            MtlswrapTheme(darkTheme = isTv || isSystemInDarkTheme()) {
                CompositionLocalProvider(LocalIsTv provides isTv) {
                    // Edge-to-edge imposé en targetSdk 36 : les Scaffold gèrent barres
                    // système et clavier, mais pas l'encoche latérale en paysage.
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
