package com.douxev.mtls_bridge.keystore

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

/**
 * Provides the SQLCipher passphrase. 32 random bytes are generated once,
 * encrypted in `EncryptedSharedPreferences` backed by a non-exportable AES
 * master key from the Android Keystore, then read back on every DB open.
 *
 * Why this indirection rather than deriving directly from the Keystore:
 * the Keystore can encrypt/decrypt but does not provide a stable secret
 * usable as a SQLCipher passphrase without a decrypt() cycle on every start.
 * EncryptedSharedPreferences does exactly that internally with a Keystore
 * master key, so there is no need to reinvent the wheel.
 */
class DbPassphraseProvider(private val context: Context) {

    fun obtainPassphrase(): ByteArray {
        // The alias passed to the Builder must match the KeyGenParameterSpec
        // one, otherwise MasterKey.build() throws: this was the main cause of
        // the startup crash seen in the first version.
        val keyAlias = "mtls_bridge-db-master"
        val masterKey = MasterKey.Builder(context, keyAlias)
            .setKeyGenParameterSpec(
                KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            .build()

        val prefs = EncryptedSharedPreferences.create(
            context,
            "mtls_bridge-secrets",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )

        val existing = prefs.getString(KEY_DB_PASS, null)
        if (existing != null) {
            return android.util.Base64.decode(existing, android.util.Base64.NO_WRAP)
        }
        val fresh = ByteArray(32).also { SecureRandom().nextBytes(it) }
        prefs.edit {
            putString(KEY_DB_PASS, android.util.Base64.encodeToString(fresh, android.util.Base64.NO_WRAP))
        }
        return fresh
    }

    private companion object {
        const val KEY_DB_PASS = "db_passphrase_b64"
    }
}
