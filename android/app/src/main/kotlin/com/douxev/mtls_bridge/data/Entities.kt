package com.douxev.mtls_bridge.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Operating mode chosen per config.
 *
 * - VPN: VpnService with addAllowedApplication(targetPackage). Isolation is
 *   guaranteed by the OS; supports several apps at once with distinct certs.
 * - LOOPBACK: 127.0.0.1:ephemeral port, per-accept UID check via
 *   ConnectivityManager.getConnectionOwnerUid. Coexists with other VPNs.
 */
enum class ProxyMode { VPN, LOOPBACK }

/**
 * Hardware attestation level of the imported key. Filled in after import
 * via `KeyInfo.getSecurityLevel()`.
 */
enum class KeySecurityLevel { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN }

@Entity(
    tableName = "configs",
    indices = [
        // 1 config = 1 app: strict uniqueness on the target package. If the
        // user wants the same cert for two apps, they create two configs with
        // two key pairs (.p12 or copy). This is deliberately explicit so that
        // routing by UID/IP is never ambiguous.
        Index(value = ["targetPackage"], unique = true),
        Index(value = ["displayName"], unique = true),
    ],
)
data class ConfigEntity(
    @PrimaryKey val id: String, // UUID
    val displayName: String,
    val targetPackage: String,
    val upstreamHost: String,
    val upstreamPort: Int,
    val sni: String?,
    val caPem: ByteArray,
    val certChainPem: ByteArray,
    val keystoreAlias: String,
    val mode: ProxyMode,
    val syntheticIp: String?, // VPN only: TEST-NET IP 192.0.2.X
    val syntheticPort: Int?, // VPN only
    val loopbackPort: Int?, // LOOPBACK only: 0 = ephemeral
    val securityLevel: KeySecurityLevel,
    val createdAtEpochMs: Long,
    /**
     * Loopback only: if true, the service is started and stays active.
     * Can be turned off from the config card (Switch). Defaults to true on
     * creation. Ignored for VPN-mode configs (driven globally by the list
     * toggle).
     */
    val enabled: Boolean = true,
    /**
     * `true` after an import from an export file: the Keystore private key is
     * missing on this device (non-exportable from the other one). The UI shows
     * a "missing key" badge and blocks the proxy from starting until the user
     * provides their .p12 again via the "Import key" button on the config
     * detail screen.
     */
    val needsKeystoreRefresh: Boolean = false,
    /**
     * Loopback: optional secret token inserted into the HTTP path to isolate
     * this config from the other apps on the device. Effective URL:
     * `http://127.0.0.1:PORT/<pathToken>/`. The proxy rejects (fail-closed)
     * requests whose path does not start with this prefix. Replaces the UID
     * defense, which is useless on Android for non-VPN apps.
     * `null` means no check (plain URL http://127.0.0.1:PORT/).
     */
    val pathToken: String? = null,
    /**
     * Loopback: additional canonical hosts (without scheme) that the proxy
     * rewrites to its loopback URL, when the server emits a name other than
     * [upstreamHost] (e.g. Nextcloud `overwrite.cli.url`). Stored normalized,
     * comma-separated; see [CanonicalHosts]. `null` means none.
     */
    val extraCanonicalHosts: String? = null,
) {
    // Room requires manual equals/hashCode with ByteArray fields (which
    // otherwise compare by identity, breaking Flow diffs).
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ConfigEntity) return false
        return id == other.id &&
            displayName == other.displayName &&
            targetPackage == other.targetPackage &&
            upstreamHost == other.upstreamHost &&
            upstreamPort == other.upstreamPort &&
            sni == other.sni &&
            caPem.contentEquals(other.caPem) &&
            certChainPem.contentEquals(other.certChainPem) &&
            keystoreAlias == other.keystoreAlias &&
            mode == other.mode &&
            syntheticIp == other.syntheticIp &&
            syntheticPort == other.syntheticPort &&
            loopbackPort == other.loopbackPort &&
            securityLevel == other.securityLevel &&
            createdAtEpochMs == other.createdAtEpochMs &&
            enabled == other.enabled &&
            needsKeystoreRefresh == other.needsKeystoreRefresh &&
            pathToken == other.pathToken &&
            extraCanonicalHosts == other.extraCanonicalHosts
    }

    override fun hashCode(): Int {
        var r = id.hashCode()
        r = 31 * r + displayName.hashCode()
        r = 31 * r + targetPackage.hashCode()
        r = 31 * r + upstreamHost.hashCode()
        r = 31 * r + upstreamPort
        r = 31 * r + (sni?.hashCode() ?: 0)
        r = 31 * r + caPem.contentHashCode()
        r = 31 * r + certChainPem.contentHashCode()
        r = 31 * r + keystoreAlias.hashCode()
        r = 31 * r + mode.hashCode()
        r = 31 * r + (syntheticIp?.hashCode() ?: 0)
        r = 31 * r + (syntheticPort ?: 0)
        r = 31 * r + (loopbackPort ?: 0)
        r = 31 * r + securityLevel.hashCode()
        r = 31 * r + createdAtEpochMs.hashCode()
        r = 31 * r + enabled.hashCode()
        r = 31 * r + needsKeystoreRefresh.hashCode()
        r = 31 * r + (pathToken?.hashCode() ?: 0)
        r = 31 * r + (extraCanonicalHosts?.hashCode() ?: 0)
        return r
    }
}

/** Encoding of [ConfigEntity.extraCanonicalHosts] (single text column). */
object CanonicalHosts {
    /**
     * Free-form input (commas, spaces or newlines) to stored value.
     * Tolerates a scheme or path pasted by mistake; `null` if empty. A
     * `:port` is kept (the core rewrites `https://<host[:port]>`).
     */
    fun normalize(input: String?): String? =
        parse(input).takeIf { it.isNotEmpty() }?.joinToString(",")

    fun parse(stored: String?): List<String> =
        stored.orEmpty()
            .split(',', ' ', '\n', '\t', ';')
            .map { h ->
                h.trim()
                    .lowercase()
                    .removePrefix("https://").removePrefix("http://")
                    .substringBefore('/')
            }
            .filter { it.isNotEmpty() }
            .distinct()
}

@Entity(
    tableName = "audit_events",
    indices = [Index(value = ["configId", "timestampMs"])],
)
data class AuditEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "configId") val configId: String,
    @ColumnInfo(name = "timestampMs") val timestampMs: Long,
    val eventType: String,
    val details: String,
)
