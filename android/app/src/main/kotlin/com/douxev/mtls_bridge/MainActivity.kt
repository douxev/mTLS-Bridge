package com.douxev.mtls_bridge

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.douxev.mtls_bridge.ui.navigation.MtlsNavigation
import com.douxev.mtls_bridge.ui.theme.MtlswrapTheme

class MainActivity : ComponentActivity() {

    // API 33+ : sans cette permission, la notification persistante du
    // ForegroundService est silencieusement supprimée → la doxev ne voit
    // pas que les proxies tournent ni le bouton "Arrêter" de la notif.
    private val requestNotifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* result ignoré — l'utilisatrice peut refuser, on continue sans notif */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ensureNotificationPermission()
        enableEdgeToEdge()
        setContent {
            MtlswrapTheme {
                MtlsNavigation()
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
