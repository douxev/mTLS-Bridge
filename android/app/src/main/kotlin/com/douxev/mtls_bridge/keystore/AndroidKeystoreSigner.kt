package com.douxev.mtls_bridge.keystore

import android.security.keystore.KeyProperties
import com.douxev.mtls_bridge.ffi.KeystoreSigner
import com.douxev.mtls_bridge.ffi.SignerException
import com.douxev.mtls_bridge.ffi.TlsSignatureScheme
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/**
 * Kotlin implementation of the [KeystoreSigner] trait (exposed via uniffi).
 *
 * Each call to [sign]:
 *  1. fetches the `PrivateKey` from the Keystore by its alias,
 *  2. creates `Signature.getInstance(jcaAlgo)` (RSA or ECDSA, SHA256/384/512,
 *     PSS or PKCS1),
 *  3. `initSign(privateKey)`: the `PrivateKey` object is only a handle to the
 *     TEE, the signature itself runs in hardware,
 *  4. `update(data) + sign()`: the bytes are returned to rustls.
 *
 * No copy of the key material is ever made on the JVM side.
 */
class AndroidKeystoreSigner : KeystoreSigner {

    private val androidKs: KeyStore by lazy {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }

    override fun sign(
        keyHandle: String,
        scheme: TlsSignatureScheme,
        `data`: ByteArray,
    ): ByteArray {
        val privateKey = (androidKs.getKey(keyHandle, null) as? PrivateKey)
            ?: throw SignerException.KeyUnavailable("alias $keyHandle not found")

        val (jcaAlgo, params) = mapScheme(scheme)
        try {
            val sig = Signature.getInstance(jcaAlgo)
            params?.let { sig.setParameter(it) }
            sig.initSign(privateKey)
            sig.update(`data`)
            return sig.sign()
        } catch (t: Throwable) {
            throw SignerException.Failed(t.message ?: t::class.java.simpleName)
        }
    }

    override fun supportedSchemes(keyHandle: String): List<TlsSignatureScheme> {
        val pk = (androidKs.getKey(keyHandle, null) as? PrivateKey)
            ?: return emptyList()
        return when (pk.algorithm) {
            KeyProperties.KEY_ALGORITHM_EC -> {
                // TLS 1.3 binds the ECDSA scheme to the key's curve: a P-384
                // key can only sign with ecdsa_secp384r1_sha384. The curve is
                // read from the cert's public key (reliable, unlike a default
                // on KeyInfo); unknown curve (P-521...) means nothing.
                val curveBits = (androidKs.getCertificate(keyHandle)?.publicKey as? ECPublicKey)
                    ?.params?.curve?.field?.fieldSize
                when (curveBits) {
                    256 -> listOf(TlsSignatureScheme.ECDSA_NISTP256_SHA256)
                    384 -> listOf(TlsSignatureScheme.ECDSA_NISTP384_SHA384)
                    else -> emptyList()
                }
            }
            KeyProperties.KEY_ALGORITHM_RSA -> {
                // RSA can do PSS and PKCS1 with every common hash.
                // TLS 1.3 only accepts PSS for RSA; both are listed to keep
                // TLS 1.2 working with old backends.
                listOf(
                    TlsSignatureScheme.RSA_PSS_SHA256,
                    TlsSignatureScheme.RSA_PSS_SHA384,
                    TlsSignatureScheme.RSA_PSS_SHA512,
                    TlsSignatureScheme.RSA_PKCS1_SHA256,
                    TlsSignatureScheme.RSA_PKCS1_SHA384,
                    TlsSignatureScheme.RSA_PKCS1_SHA512,
                )
            }
            else -> emptyList()
        }
    }

    private fun mapScheme(
        scheme: TlsSignatureScheme,
    ): Pair<String, AlgorithmParameterSpec?> = when (scheme) {
        TlsSignatureScheme.ECDSA_NISTP256_SHA256 -> "SHA256withECDSA" to null
        TlsSignatureScheme.ECDSA_NISTP384_SHA384 -> "SHA384withECDSA" to null
        TlsSignatureScheme.RSA_PKCS1_SHA256 -> "SHA256withRSA" to null
        TlsSignatureScheme.RSA_PKCS1_SHA384 -> "SHA384withRSA" to null
        TlsSignatureScheme.RSA_PKCS1_SHA512 -> "SHA512withRSA" to null
        TlsSignatureScheme.RSA_PSS_SHA256 -> "SHA256withRSA/PSS" to pssParams("SHA-256", 32)
        TlsSignatureScheme.RSA_PSS_SHA384 -> "SHA384withRSA/PSS" to pssParams("SHA-384", 48)
        TlsSignatureScheme.RSA_PSS_SHA512 -> "SHA512withRSA/PSS" to pssParams("SHA-512", 64)
    }

    private fun pssParams(hash: String, saltLen: Int) = PSSParameterSpec(
        hash, "MGF1", MGF1ParameterSpec(hash), saltLen, 1
    )
}
