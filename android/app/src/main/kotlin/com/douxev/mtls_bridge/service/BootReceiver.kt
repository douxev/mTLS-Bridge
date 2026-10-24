package com.douxev.mtls_bridge.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.douxev.mtls_bridge.MtlsApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Relance les proxys loopback `enabled` au démarrage de l'appareil et après
 * une mise à jour de l'app. Indispensable sur Android TV : le téléviseur
 * redémarre souvent (veille profonde, coupure secteur) et l'utilisatrice
 * lance Jellyfin directement depuis l'écran d'accueil, sans ouvrir mTLS
 * Bridge. Démarrer un service de premier plan depuis BOOT_COMPLETED est
 * autorisé pour le type `specialUse`.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED -> {
                Log.i(TAG, "${intent.action} : restauration des proxys actifs")
                (context.applicationContext as MtlsApplication).startLoopbackCoordinator()
                // Le coordinateur lit la base chiffrée puis démarre le service
                // de façon asynchrone : on garde le process en vie le temps
                // qu'il le fasse (le service le maintient ensuite).
                val pending = goAsync()
                CoroutineScope(Dispatchers.Default).launch {
                    delay(START_GRACE_MS)
                    pending.finish()
                }
            }
        }
    }

    private companion object {
        const val TAG = "mtls_bridge.boot"
        const val START_GRACE_MS = 8_000L
    }
}
