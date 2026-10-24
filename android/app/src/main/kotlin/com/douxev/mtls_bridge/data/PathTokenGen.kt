package com.douxev.mtls_bridge.data

import java.security.SecureRandom

/**
 * Génère un token URL-safe pour le path-isolation côté loopback.
 *
 * Alphabet sans caractères ambigus (pas de 0/O, 1/l/I) pour qu'une doxev
 * puisse retaper le token à la main en cas de besoin. 12 chars × log2(54)
 * ≈ 69 bits d'entropie : largement au-dessus de ce qu'un scan brute-force
 * peut espérer faire sur un port loopback.
 */
object PathTokenGen {
    private const val ALPHABET =
        "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
    private const val LEN = 12
    private val rng = SecureRandom()

    fun generate(): String {
        val a = ALPHABET
        return buildString(LEN) {
            repeat(LEN) { append(a[rng.nextInt(a.length)]) }
        }
    }
}
