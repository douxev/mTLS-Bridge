package com.douxev.mtls_bridge.runtime

import android.content.Context
import android.net.Uri
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Attempts to delete a file picked via SAF (`content://`). This is
 * best-effort: depending on the source provider (Downloads, Drive,
 * Snapchat...), deletion may be silently refused. It is logged and ignored.
 *
 * For local files picked via ACTION_GET_CONTENT (our case), deletion usually
 * works with Downloads / user files.
 */
object SafFileUtils {
    private const val TAG = "mtls_bridge.saf"

    /** Reads the whole content of a `content://` URI (provider may be slow: IO). */
    suspend fun readBytes(context: Context, uri: Uri): ByteArray = withContext(Dispatchers.IO) {
        context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: error("cannot read $uri")
    }

    suspend fun writeBytes(context: Context, uri: Uri, bytes: ByteArray) = withContext(Dispatchers.IO) {
        context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
            ?: error("cannot write $uri")
    }

    suspend fun deleteIfPossible(context: Context, uri: Uri): Boolean = withContext(Dispatchers.IO) {
        try {
            val rows = context.contentResolver.delete(uri, null, null)
            if (rows > 0) {
                Log.i(TAG, "deleted: $uri")
                true
            } else {
                Log.w(TAG, "deletion refused by the provider: $uri")
                false
            }
        } catch (t: Throwable) {
            Log.w(TAG, "delete($uri) failed: ${t.message}")
            false
        }
    }
}
