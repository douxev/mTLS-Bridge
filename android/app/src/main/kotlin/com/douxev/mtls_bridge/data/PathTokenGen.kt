package com.douxev.mtls_bridge.data

import java.security.SecureRandom

/**
 * Generates a URL-safe token for loopback path isolation.
 *
 * The alphabet has no ambiguous characters (no 0/O, 1/l/I) so the user can
 * retype the token by hand if needed. 12 chars x log2(54) = ~69 bits of
 * entropy: far beyond what a brute-force scan can hope to achieve on a
 * loopback port.
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
