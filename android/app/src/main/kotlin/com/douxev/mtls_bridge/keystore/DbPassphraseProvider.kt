package com.douxev.mtls_bridge.keystore

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

/**
 * Fournit la passphrase de SQLCipher. On génère une fois 32 octets aléatoires,
 * on les chiffre dans des `EncryptedSharedPreferences` adossés à un AES master-key
 * non-exportable du Keystore Android, puis on les relit à chaque ouverture DB.
 *
 * Pourquoi cette indirection plutôt que dériver directement depuis Keystore :
 * Keystore peut chiffrer/déchiffrer mais ne donne pas un secret stable
 * réutilisable comme passphrase SQLCipher sans un cycle decrypt() à chaque
 * démarrage. EncryptedSharedPreferences fait exactement ça en interne avec un
 * master-key Keystore → on ne réinvente pas la roue.
 */
class DbPassphraseProvider(private val context: Context) {

    fun obtainPassphrase(): ByteArray {
        // L'alias passé au Builder doit matcher celui du KeyGenParameterSpec,
        // sinon MasterKey.build() throw — c'est la cause #1 du crash startup
        // observé sur la première version.
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
