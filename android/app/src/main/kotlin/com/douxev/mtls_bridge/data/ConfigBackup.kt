package com.douxev.mtls_bridge.data

import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.json.JSONArray
import org.json.JSONObject

/**
 * Format d'export portable des configs : **archive zip** contenant
 *
 * ```
 * configs.json                        # métadonnées + références vers fichiers
 * README.txt                          # explication du format
 * <configId>-cert.pem                 # chaîne de certs client (PEM)
 * <configId>-ca.pem                   # CA upstream pinné (PEM)
 * <configId>.p12                      # [optionnel] clé + cert chiffré PKCS#12
 * ```
 *
 * Deux cas d'usage couverts par le **même format** :
 *
 * **(A) Personal backup** : export depuis l'app pour migrer entre devices.
 * Le .p12 **n'est PAS inclus** (la clé privée est non-exportable du Keystore
 * matériel). Chaque config est marquée `needsKeystoreRefresh=true` à
 * l'import → la doxev re-fournit son .p12 d'origine via "Importer la clé".
 *
 * **(B) Deployment bundle** : un IT admin génère le bundle depuis l'extérieur
 * de l'app (script bash + openssl + zip). Il inclut le .p12 chiffré par
 * passphrase. L'employé clique sur le bundle, saisit la passphrase une fois,
 * toutes les configs sont immédiatement opérationnelles. Voir
 * `docs/deployment-bundle.md` pour le script de génération type.
 *
 * Format documenté dans docs/threat-model.md §9.
 */
object ConfigBackup {

    const val SCHEMA_VERSION = 2 // v2 = zip ; v1 était le JSON inline (abandonné)
    private const val CONFIGS_JSON = "configs.json"
    private const val README = "README.txt"

    private val README_BODY = """
        mTLS Bridge bundle — schéma v$SCHEMA_VERSION

        Ce zip contient :
        - configs.json   : métadonnées des configurations
        - <id>-cert.pem  : chaîne de certs client pour la config <id>
        - <id>-ca.pem    : CA upstream pinnée pour la config <id>
        - <id>.p12       : [optionnel] PKCS#12 chiffré contenant la clé privée

        Sans .p12 (export depuis l'app) : import en mode "backup", la doxev
        re-fournit son .p12 d'origine manuellement.

        Avec .p12 (bundle de déploiement IT) : import direct, demande la
        passphrase une fois pour tout le bundle.

        Inspection : openssl x509 -in <id>-cert.pem -text
                     openssl pkcs12 -in <id>.p12 -info
    """.trimIndent()

    fun export(configs: List<ConfigEntity>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zip ->
            zip.putEntry(README, README_BODY.toByteArray(Charsets.UTF_8))
            zip.putEntry(CONFIGS_JSON, buildJson(configs).toByteArray(Charsets.UTF_8))
            for (c in configs) {
                zip.putEntry("${c.id}-cert.pem", c.certChainPem)
                zip.putEntry("${c.id}-ca.pem", c.caPem)
            }
        }
        return baos.toByteArray()
    }

    private fun ZipOutputStream.putEntry(name: String, data: ByteArray) {
        putNextEntry(ZipEntry(name))
        write(data)
        closeEntry()
    }

    private fun buildJson(configs: List<ConfigEntity>): String {
        val root = JSONObject().apply {
            put("schema", SCHEMA_VERSION)
            put("exportedAtMs", System.currentTimeMillis())
            put("configs", JSONArray().apply {
                for (c in configs) put(serializeConfig(c))
            })
        }
        return root.toString(2)
    }

    private fun serializeConfig(c: ConfigEntity): JSONObject = JSONObject().apply {
        put("id", c.id)
        put("displayName", c.displayName)
        put("targetPackage", c.targetPackage)
        put("upstreamHost", c.upstreamHost)
        put("upstreamPort", c.upstreamPort)
        put("sni", c.sni)
        // Informatif seulement (lu par les anciennes versions) : l'import
        // génère toujours un alias Keystore local neuf.
        put("keystoreAlias", c.keystoreAlias)
        put("mode", c.mode.name)
        put("syntheticIp", c.syntheticIp)
        put("syntheticPort", c.syntheticPort ?: JSONObject.NULL)
        put("loopbackPort", c.loopbackPort ?: JSONObject.NULL)
        put("enabled", c.enabled)
        put("certPemFile", "${c.id}-cert.pem")
        put("caPemFile", "${c.id}-ca.pem")
        // pathToken optionnel : présent si la config a un token loopback.
        put("pathToken", c.pathToken ?: JSONObject.NULL)
        put("extraCanonicalHosts", JSONArray(CanonicalHosts.parse(c.extraCanonicalHosts)))
        // p12File optionnel : non émis par l'export app (on n'a pas la clé).
        // Présent uniquement dans les bundles de déploiement IT.
    }

    /**
     * Une config parsée depuis un bundle. `p12Bytes != null` ⇒ deployment
     * bundle, on importera le .p12 dans Keystore avec la passphrase fournie.
     * Sinon ⇒ personal backup, needsKeystoreRefresh=true.
     */
    data class ParsedConfig(
        val entity: ConfigEntity,
        val p12Bytes: ByteArray?,
    )

    fun parse(zipBytes: ByteArray): List<ParsedConfig> {
        // Première passe : on lit le zip dans une map nom → bytes pour éviter
        // les hypothèses sur l'ordre des entries.
        val files = mutableMapOf<String, ByteArray>()
        ZipInputStream(zipBytes.inputStream()).use { zip ->
            while (true) {
                val e = zip.nextEntry ?: break
                if (!e.isDirectory) {
                    files[e.name] = zip.readBytes()
                }
                zip.closeEntry()
            }
        }
        val configsJson = files[CONFIGS_JSON]
            ?: error("zip invalide : pas de $CONFIGS_JSON")
        val root = JSONObject(String(configsJson, Charsets.UTF_8))
        val schema = root.getInt("schema")
        require(schema == SCHEMA_VERSION) {
            "schéma de bundle $schema non supporté (attendu $SCHEMA_VERSION)"
        }
        val arr = root.getJSONArray("configs")
        return (0 until arr.length()).map { i ->
            deserializeConfig(arr.getJSONObject(i), files)
        }
    }

    private fun deserializeConfig(o: JSONObject, files: Map<String, ByteArray>): ParsedConfig {
        val certPemFile = o.getString("certPemFile")
        val caPemFile = o.getString("caPemFile")
        val certChainPem = files[certPemFile]
            ?: error("zip incomplet : $certPemFile manquant")
        val caPem = files[caPemFile]
            ?: error("zip incomplet : $caPemFile manquant")
        // Champ optionnel pour les bundles de déploiement IT.
        val p12Bytes: ByteArray? = if (o.has("p12File") && !o.isNull("p12File")) {
            val p12File = o.getString("p12File")
            files[p12File] ?: error("zip incomplet : $p12File manquant")
        } else null
        val entity = ConfigEntity(
            id = o.getString("id"),
            displayName = o.getString("displayName"),
            targetPackage = o.getString("targetPackage"),
            upstreamHost = o.getString("upstreamHost"),
            upstreamPort = o.getInt("upstreamPort"),
            sni = o.optString("sni").takeIf { it.isNotEmpty() && it != "null" },
            caPem = caPem,
            certChainPem = certChainPem,
            // Alias du bundle ignoré : ConfigRepository.importZip en génère un
            // neuf (un bundle ne doit jamais pouvoir viser une clé existante).
            keystoreAlias = "",
            mode = ProxyMode.valueOf(o.getString("mode")),
            syntheticIp = if (o.isNull("syntheticIp")) null else o.getString("syntheticIp"),
            syntheticPort = if (o.isNull("syntheticPort")) null else o.getInt("syntheticPort"),
            loopbackPort = if (o.isNull("loopbackPort")) null else o.getInt("loopbackPort"),
            securityLevel = KeySecurityLevel.UNKNOWN,
            createdAtEpochMs = System.currentTimeMillis(),
            // Avec .p12 : on active dès l'import après import Keystore réussi.
            // Sans .p12 : needsKeystoreRefresh=true, désactivée.
            enabled = p12Bytes != null,
            needsKeystoreRefresh = p12Bytes == null,
            pathToken = if (o.has("pathToken") && !o.isNull("pathToken"))
                o.getString("pathToken").takeIf { it.isNotBlank() }
            else null,
            extraCanonicalHosts = parseExtraCanonicalHosts(o),
        )
        return ParsedConfig(entity, p12Bytes)
    }

    /** Champ optionnel : tableau JSON (format d'export) ou chaîne séparée par des virgules. */
    private fun parseExtraCanonicalHosts(o: JSONObject): String? {
        if (!o.has("extraCanonicalHosts") || o.isNull("extraCanonicalHosts")) return null
        val arr = o.optJSONArray("extraCanonicalHosts")
        val raw = if (arr != null) {
            (0 until arr.length()).joinToString(",") { arr.optString(it) }
        } else {
            o.optString("extraCanonicalHosts")
        }
        return CanonicalHosts.normalize(raw)
    }
}
