package com.douxev.mtls_bridge.runtime

import android.content.Context
import android.net.Uri
import android.util.Log

/**
 * Tente de supprimer un fichier pické via SAF (`content://`). C'est
 * best-effort : selon le provider source (Downloads, Drive, Snapchat…),
 * la suppression peut être refusée silencieusement. On log et on continue.
 *
 * Pour des fichiers locaux picked via ACTION_GET_CONTENT (notre cas), la
 * suppression marche habituellement avec les Downloads / fichiers utilisateur.
 */
object SafFileUtils {
    private const val TAG = "mtls_bridge.saf"

    fun deleteIfPossible(context: Context, uri: Uri): Boolean = try {
        val rows = context.contentResolver.delete(uri, null, null)
        if (rows > 0) {
            Log.i(TAG, "supprimé : $uri")
            true
        } else {
            Log.w(TAG, "suppression refusée par le provider : $uri")
            false
        }
    } catch (t: Throwable) {
        Log.w(TAG, "delete($uri) a échoué : ${t.message}")
        false
    }
}
