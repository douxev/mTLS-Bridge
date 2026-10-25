package com.douxev.mtls_bridge.remote

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocketFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.security.auth.x500.X500Principal

/**
 * TLS for the LAN admin console.
 *
 * The .p12 and its passphrase travel from the browser to the device: sending
 * them in clear text over Wi-Fi is out of the question. So the console is
 * served over HTTPS with a self-signed certificate whose EC P-256 key is
 * generated **inside** the Android Keystore (non-exportable). The browser
 * will show a warning (no certificate authority): the device screen shows the
 * SHA-256 fingerprint so the user can compare it.
 */
internal object RemoteTls {
    private const val ALIAS = "mtls_bridge-remote-admin-tls"

    class Material(
        val socketFactory: SSLServerSocketFactory,
        /** SHA-256 fingerprint of the certificate, `AB:CD:...` format (32 bytes). */
        val fingerprint: String,
    )

    fun material(): Material {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(ALIAS)) generate()
        val entry = ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
        val cert = entry.certificate as X509Certificate
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(arrayOf(KeystoreKeyManager(entry.privateKey, arrayOf(cert))), null, null)
        return Material(ctx.serverSocketFactory, fingerprintOf(cert))
    }

    private fun generate() {
        val now = System.currentTimeMillis()
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // DIGEST_NONE: Conscrypt delegates the TLS signature by passing an
            // already computed digest (NONEwithECDSA).
            .setDigests(
                KeyProperties.DIGEST_NONE,
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512,
            )
            .setCertificateSubject(X500Principal("CN=mTLS Bridge remote admin"))
            .setCertificateSerialNumber(BigInteger.valueOf(now))
            .setCertificateNotBefore(Date(now - DAY_MS))
            .setCertificateNotAfter(Date(now + 10 * 365 * DAY_MS))
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun fingerprintOf(cert: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            .joinToString(":") { "%02X".format(it) }

    /**
     * Minimal KeyManager: `KeyManagerFactory` cannot reliably read
     * AndroidKeyStore entries on every version, so the key (TEE handle) and
     * the cert are returned directly.
     */
    private class KeystoreKeyManager(
        private val key: PrivateKey,
        private val chain: Array<X509Certificate>,
    ) : X509ExtendedKeyManager() {
        private fun aliasFor(keyType: String?): String? =
            if (keyType == null || keyType.startsWith("EC")) ALIAS else null

        override fun getClientAliases(
            keyType: String?,
            issuers: Array<out Principal>?,
        ): Array<String>? = null

        override fun chooseClientAlias(
            keyType: Array<out String>?,
            issuers: Array<out Principal>?,
            socket: Socket?,
        ): String? = null

        override fun getServerAliases(
            keyType: String?,
            issuers: Array<out Principal>?,
        ): Array<String>? = aliasFor(keyType)?.let { arrayOf(it) }

        override fun chooseServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            socket: Socket?,
        ): String? = aliasFor(keyType)

        override fun chooseEngineServerAlias(
            keyType: String?,
            issuers: Array<out Principal>?,
            engine: SSLEngine?,
        ): String? = aliasFor(keyType)

        override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
            if (alias == ALIAS) chain else null

        override fun getPrivateKey(alias: String?): PrivateKey? =
            if (alias == ALIAS) key else null
    }

    private const val DAY_MS = 24L * 60 * 60 * 1000
}
