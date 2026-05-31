package com.douxev.mtls_bridge.keystore

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import com.douxev.mtls_bridge.data.KeySecurityLevel
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

data class P12ImportResult(
    val keystoreAlias: String,
    val certChainPem: ByteArray,
    val securityLevel: KeySecurityLevel,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is P12ImportResult) return false
        return keystoreAlias == other.keystoreAlias &&
            certChainPem.contentEquals(other.certChainPem) &&
            securityLevel == other.securityLevel
    }

    override fun hashCode(): Int = (keystoreAlias.hashCode() * 31 +
        certChainPem.contentHashCode()) * 31 + securityLevel.hashCode()
}

/**
 * Importe un .p12 dans le Keystore Android et renvoie la chaîne de certs
 * (PEM, leaf en premier) + le niveau d'attestation effectivement obtenu.
 *
 * Limites assumées :
 * - La clé est importée via `setKeyEntry`. Sur la plupart des devices Android
 *   modernes (API 28+ avec implémentation OEM correcte), elle finit
 *   hardware-backed via le mécanisme d'import-into-TEE du Keymint daemon.
 *   Sur les anciens devices ou ROMs custom, elle peut rester software-backed —
 *   on le signale via `securityLevel` pour que l'UI prévienne la doxev.
 * - Une fois importée, la clé est non-exportable. Aucun chemin de code ne peut
 *   en récupérer le matériel cryptographique.
 */
class P12Importer {

    fun import(
        p12Bytes: ByteArray,
        passphrase: CharArray,
        keystoreAlias: String,
    ): P12ImportResult {
        // 1. Parser le .p12 en mémoire.
        val p12 = KeyStore.getInstance("PKCS12")
        p12.load(ByteArrayInputStream(p12Bytes), passphrase)

        val alias = p12.aliases().toList().firstOrNull()
            ?: error("aucun alias dans le .p12")
        val privateKey = p12.getKey(alias, passphrase) as? PrivateKey
            ?: error("alias .p12 sans clé privée")
        val chain: Array<X509Certificate> = (p12.getCertificateChain(alias) ?: emptyArray())
            .map { it as X509Certificate }
            .toTypedArray()
        check(chain.isNotEmpty()) { "chaîne de certs vide dans le .p12" }

        // 2. Préparer la KeyProtection — on demande le hardware quand dispo
        //    et on autorise les schémas de signature TLS courants.
        val protection = KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512,
            )
            .setSignaturePaddings(
                KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                KeyProperties.SIGNATURE_PADDING_RSA_PSS,
            )
            .setUserAuthenticationRequired(false)
            .build()

        // 3. Importer dans AndroidKeyStore.
        val androidKs = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        // On efface une éventuelle entrée précédente avec ce même alias (édition d'une config).
        if (androidKs.containsAlias(keystoreAlias)) {
            androidKs.deleteEntry(keystoreAlias)
        }
        androidKs.setEntry(
            keystoreAlias,
            KeyStore.PrivateKeyEntry(privateKey, chain.toList<X509Certificate>().toTypedArray()),
            protection,
        )

        // 4. Inspecter le niveau d'attestation obtenu.
        val imported = androidKs.getKey(keystoreAlias, null) as PrivateKey
        val securityLevel = querySecurityLevel(imported)

        // 5. Sérialiser la chaîne en PEM pour la passer au core Rust.
        val certChainPem = chain.joinToString(separator = "\n") { certToPem(it) }
            .toByteArray(Charsets.US_ASCII)

        return P12ImportResult(keystoreAlias, certChainPem, securityLevel)
    }

    private fun querySecurityLevel(key: PrivateKey): KeySecurityLevel = try {
        val factory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(key, KeyInfo::class.java)
        // KeyInfo.getSecurityLevel() existe en API 31+. Sur API 29/30 on
        // retombe sur isInsideSecureHardware() (déprécié mais dispo).
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
                else -> KeySecurityLevel.UNKNOWN
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) KeySecurityLevel.TRUSTED_ENVIRONMENT
            else KeySecurityLevel.SOFTWARE
        }
    } catch (_: Throwable) {
        KeySecurityLevel.UNKNOWN
    }

    private fun certToPem(cert: X509Certificate): String {
        val b64 = android.util.Base64.encodeToString(cert.encoded, android.util.Base64.NO_WRAP)
        val wrapped = b64.chunked(64).joinToString("\n")
        return "-----BEGIN CERTIFICATE-----\n$wrapped\n-----END CERTIFICATE-----"
    }
}
