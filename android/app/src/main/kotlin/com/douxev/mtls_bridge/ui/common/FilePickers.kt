package com.douxev.mtls_bridge.ui.common

import android.content.ActivityNotFoundException
import android.content.Context
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import com.douxev.mtls_bridge.R

/**
 * Launches a file picker (GetContent / CreateDocument). Many Google TV /
 * Android TV devices have no app able to handle it: `launch` then throws
 * ActivityNotFoundException, which used to crash the app. Instead, explain
 * how to transfer the files.
 */
fun <I> ActivityResultLauncher<I>.launchOrExplain(context: Context, input: I): Boolean =
    try {
        launch(input)
        true
    } catch (_: ActivityNotFoundException) {
        Toast.makeText(
            context,
            context.getString(R.string.common_no_file_picker),
            Toast.LENGTH_LONG,
        ).show()
        false
    }
