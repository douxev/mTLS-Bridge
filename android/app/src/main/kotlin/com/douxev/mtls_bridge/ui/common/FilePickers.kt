package com.douxev.mtls_bridge.ui.common

import android.content.ActivityNotFoundException
import android.content.Context
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher

/**
 * Lance un sélecteur de fichiers (GetContent / CreateDocument). Beaucoup de
 * téléviseurs Google TV / Android TV n'ont aucune app capable de les servir :
 * `launch` lève alors ActivityNotFoundException et faisait planter l'app.
 * On explique plutôt comment faire passer les fichiers.
 */
fun <I> ActivityResultLauncher<I>.launchOrExplain(context: Context, input: I): Boolean =
    try {
        launch(input)
        true
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(
            context,
            "Aucun sélecteur de fichiers sur cet appareil : utilise " +
                "« Configuration à distance » depuis un ordinateur ou un smartphone.",
            Toast.LENGTH_LONG,
        ).show()
        false
    }
