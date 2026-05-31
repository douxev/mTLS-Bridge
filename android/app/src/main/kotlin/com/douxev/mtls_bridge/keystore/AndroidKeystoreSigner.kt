package com.douxev.mtls_bridge.keystore

import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.douxev.mtls_bridge.ffi.KeystoreSigner
import com.douxev.mtls_bridge.ffi.SignerException
import com.douxev.mtls_bridge.ffi.TlsSignatureScheme
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/**
 * Implémentation Kotlin du trait [KeystoreSigner] (exposé via uniffi).
 *
 * Chaque appel à [sign] :
 *  1. récupère la `PrivateKey` du Keystore via son alias,
 *  2. instancie `Signature.getInstance(jcaAlgo)` (RSA ou ECDSA, SHA256/384/512,
 *     PSS ou PKCS1),
 *  3. `initSign(privateKey)` — l'objet `PrivateKey` est juste un handle vers
 *     le TEE, la signature elle-même s'exécute dans le matériel,
 *  4. `update(data) + sign()` → bytes renvoyés à rustls.
 *
 * Aucune copie du matériel cryptographique n'est faite côté JVM.
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
            ?: throw SignerException.KeyUnavailable("alias $keyHandle introuvable")

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
                // On déduit la courbe de KeyInfo.
                val info = runCatching {
                    KeyFactory.getInstance(pk.algorithm, "AndroidKeyStore")
                        .getKeySpec(pk, KeyInfo::class.java)
                }.getOrNull()
                val size = info?.keySize ?: 256
                when {
                    size >= 384 -> listOf(
                        TlsSignatureScheme.ECDSA_NISTP384_SHA384,
                        TlsSignatureScheme.ECDSA_NISTP256_SHA256,
                    )
                    else -> listOf(TlsSignatureScheme.ECDSA_NISTP256_SHA256)
                }
            }
            KeyProperties.KEY_ALGORITHM_RSA -> {
                // RSA peut faire PSS et PKCS1 sur tous les hashs courants.
                // TLS 1.3 n'accepte que PSS pour RSA ; on liste les deux pour
                // garder TLS 1.2 fonctionnel sur les vieux backends.
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
