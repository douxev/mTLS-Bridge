package com.douxev.mtls_bridge.data

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Mode de fonctionnement choisi par config.
 *
 * - VPN : VpnService avec addAllowedApplication(targetPackage). Isolation
 *   garantie par l'OS, accepte plusieurs apps simultanément avec certs distincts.
 * - LOOPBACK : 127.0.0.1:port éphémère, UID-check par accept via
 *   ConnectivityManager.getConnectionOwnerUid. Cohabite avec d'autres VPN.
 */
enum class ProxyMode { VPN, LOOPBACK }

/**
 * Niveau d'attestation matérielle de la clé importée. Renseigné après import
 * via `KeyInfo.getSecurityLevel()`.
 */
enum class KeySecurityLevel { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN }

@Entity(
    tableName = "configs",
    indices = [
        // 1 config = 1 app : unicité forte sur le package cible. Si la doxev
        // veut utiliser le même cert pour deux apps, elle crée deux configs
        // avec deux paires (.p12 ou copie) — c'est volontairement explicite
        // pour qu'il n'y ait jamais d'ambiguïté de routage par UID/IP.
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
    val syntheticIp: String?, // VPN only — IP TEST-NET 192.0.2.X
    val syntheticPort: Int?, // VPN only
    val loopbackPort: Int?, // LOOPBACK only — 0 = éphémère
    val securityLevel: KeySecurityLevel,
    val createdAtEpochMs: Long,
    /**
     * Loopback uniquement : si true, le service est démarré et reste actif.
     * Désactivable depuis la carte de la config (Switch). Auto = true à la
     * création. Ignoré pour les configs en mode VPN (pilotage global via le
     * toggle de la liste).
     */
    val enabled: Boolean = true,
    /**
     * `true` après un import depuis un fichier d'export : la clé privée
     * Keystore est absente sur ce device (non-exportable depuis l'autre).
     * L'UI affiche un badge "clé manquante" et bloque le démarrage du proxy
     * tant que la doxev n'a pas refourni son .p12 via le bouton "Importer la
     * clé" sur le détail de la config.
     */
    val needsKeystoreRefresh: Boolean = false,
    /**
     * Loopback : token secret optionnel inséré dans le path HTTP pour isoler
     * cette config des autres apps du device. URL effective :
     * `http://127.0.0.1:PORT/<pathToken>/`. Le proxy refuse fail-closed les
     * requêtes dont le path ne commence pas par ce préfixe. Remplace la
     * défense par UID, inutile sur Android pour les apps non-VPN.
     * `null` ⇒ pas de check (URL plain http://127.0.0.1:PORT/).
     */
    val pathToken: String? = null,
    /**
     * Loopback : hôtes canoniques additionnels (sans scheme) que le proxy
     * réécrit vers son URL loopback, quand le serveur émet un autre nom que
     * [upstreamHost] (ex. Nextcloud `overwrite.cli.url`). Stocké normalisé,
     * séparé par des virgules — voir [CanonicalHosts]. `null` ⇒ aucun.
     */
    val extraCanonicalHosts: String? = null,
) {
    // Room exige equals/hashCode manuels quand on a des ByteArray (qui sinon
    // comparent par identité, ce qui casse les diffs Flow).
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

/** Encodage de [ConfigEntity.extraCanonicalHosts] (colonne texte unique). */
object CanonicalHosts {
    /**
     * Saisie libre (virgules, espaces ou retours à la ligne) → valeur stockée.
     * Tolère un scheme ou un path collés par erreur ; `null` si vide. Un
     * `:port` est conservé (le core réécrit `https://<hôte[:port]>`).
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
