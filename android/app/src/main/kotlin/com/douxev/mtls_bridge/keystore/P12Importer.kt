package com.douxev.mtls_bridge.keystore

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import com.douxev.mtls_bridge.data.KeySecurityLevel
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
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
 * Imports a .p12 into the Android Keystore and returns the cert chain
 * (PEM, leaf first) + the attestation level actually obtained.
 *
 * Accepted limitations:
 * - The key is imported via `setKeyEntry`. On most modern Android devices
 *   (API 28+ with a correct OEM implementation), it ends up hardware-backed
 *   through the KeyMint daemon's import-into-TEE mechanism. On old devices or
 *   custom ROMs it may stay software-backed; this is reported through
 *   `securityLevel` so the UI can warn the user.
 * - Once imported, the key is non-exportable. No code path can retrieve its
 *   key material.
 */
class P12Importer {

    /**
     * @param expectedLeafCertPem if provided, the leaf cert of the .p12 must be
     *   identical (DER) to the first cert of this PEM; otherwise an error is
     *   thrown **before** anything is written to the Keystore.
     */
    fun import(
        p12Bytes: ByteArray,
        passphrase: CharArray,
        keystoreAlias: String,
        expectedLeafCertPem: ByteArray? = null,
    ): P12ImportResult {
        // 1. Parse the .p12 in memory.
        val p12 = KeyStore.getInstance("PKCS12")
        p12.load(ByteArrayInputStream(p12Bytes), passphrase)

        // A .p12 may contain "trusted certificate" (CA) entries before the key
        // entry: take the first one that holds a private key.
        val alias = p12.aliases().toList().firstOrNull { p12.isKeyEntry(it) }
            ?: error("no private key in the .p12")
        val privateKey = p12.getKey(alias, passphrase) as? PrivateKey
            ?: error(".p12 alias without a private key")
        val chain: Array<X509Certificate> = (p12.getCertificateChain(alias) ?: emptyArray())
            .map { it as X509Certificate }
            .toTypedArray()
        check(chain.isNotEmpty()) { "empty certificate chain in the .p12" }
        if (expectedLeafCertPem != null) {
            val expected = CertificateFactory.getInstance("X.509")
                .generateCertificates(ByteArrayInputStream(expectedLeafCertPem))
                .firstOrNull()
                ?: error("expected certificate is unreadable")
            check(expected.encoded.contentEquals(chain[0].encoded)) {
                "the .p12 does not contain the same certificate as the config"
            }
        }

        // 2. Prepare the KeyProtection: request hardware when available and
        //    allow the common TLS signature schemes.
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

        // 3. Import into AndroidKeyStore.
        val androidKs = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        // Delete any previous entry with the same alias (editing a config).
        if (androidKs.containsAlias(keystoreAlias)) {
            androidKs.deleteEntry(keystoreAlias)
        }
        androidKs.setEntry(
            keystoreAlias,
            KeyStore.PrivateKeyEntry(privateKey, chain.toList<X509Certificate>().toTypedArray()),
            protection,
        )

        // 4. Inspect the attestation level obtained.
        val imported = androidKs.getKey(keystoreAlias, null) as PrivateKey
        val securityLevel = querySecurityLevel(imported)

        // 5. Serialize the chain as PEM to pass it to the Rust core.
        val certChainPem = chain.joinToString(separator = "\n") { certToPem(it) }
            .toByteArray(Charsets.US_ASCII)

        return P12ImportResult(keystoreAlias, certChainPem, securityLevel)
    }

    private fun querySecurityLevel(key: PrivateKey): KeySecurityLevel = try {
        val factory = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
        val info = factory.getKeySpec(key, KeyInfo::class.java)
        // KeyInfo.getSecurityLevel() exists on API 31+. On API 29/30, fall
        // back to isInsideSecureHardware() (deprecated but available).
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
