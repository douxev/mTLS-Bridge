package com.douxev.mtls_bridge.data

import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import org.json.JSONArray
import org.json.JSONObject

/**
 * Portable export format for configs: a **zip archive** containing
 *
 * ```
 * configs.json                        # metadata + references to files
 * README.txt                          # format description
 * <configId>-cert.pem                 # client certificate chain (PEM)
 * <configId>-ca.pem                   # pinned upstream CA (PEM)
 * <configId>.p12                      # [optional] key + cert, encrypted PKCS#12
 * ```
 *
 * Two use cases are covered by the **same format**:
 *
 * **(A) Personal backup**: export from the app to migrate between devices.
 * The .p12 is **NOT included** (the private key cannot be exported from the
 * hardware Keystore). Each config is flagged `needsKeystoreRefresh=true` on
 * import, and the user provides their original .p12 again via "Import key".
 *
 * **(B) Deployment bundle**: an IT admin builds the bundle outside the app
 * (bash script + openssl + zip). It includes the passphrase-encrypted .p12.
 * The employee opens the bundle, enters the passphrase once, and every config
 * is immediately operational. See `docs/deployment-bundle.md` for a sample
 * generation script.
 *
 * Format documented in docs/threat-model.md section 9.
 */
object ConfigBackup {

    const val SCHEMA_VERSION = 2 // v2 = zip; v1 was inline JSON (dropped)
    private const val CONFIGS_JSON = "configs.json"
    private const val README = "README.txt"

    private val README_BODY = """
        mTLS Bridge bundle - schema v$SCHEMA_VERSION

        This zip contains:
        - configs.json   : configuration metadata
        - <id>-cert.pem  : client certificate chain for config <id>
        - <id>-ca.pem    : pinned upstream CA for config <id>
        - <id>.p12       : [optional] encrypted PKCS#12 holding the private key

        Without .p12 (export from the app): imported in "backup" mode, the user
        provides their original .p12 again manually.

        With .p12 (IT deployment bundle): direct import, the passphrase is
        asked once for the whole bundle.

        Inspection: openssl x509 -in <id>-cert.pem -text
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
        // Informational only (read by older versions): import always
        // generates a fresh local Keystore alias.
        put("keystoreAlias", c.keystoreAlias)
        put("mode", c.mode.name)
        put("syntheticIp", c.syntheticIp)
        put("syntheticPort", c.syntheticPort ?: JSONObject.NULL)
        put("loopbackPort", c.loopbackPort ?: JSONObject.NULL)
        put("enabled", c.enabled)
        put("certPemFile", "${c.id}-cert.pem")
        put("caPemFile", "${c.id}-ca.pem")
        // Optional pathToken: present if the config has a loopback token.
        put("pathToken", c.pathToken ?: JSONObject.NULL)
        put("extraCanonicalHosts", JSONArray(CanonicalHosts.parse(c.extraCanonicalHosts)))
        // Optional p12File: never emitted by the app export (the key is not
        // available). Present only in IT deployment bundles.
    }

    /**
     * A config parsed from a bundle. `p12Bytes != null` means a deployment
     * bundle: the .p12 will be imported into the Keystore with the supplied
     * passphrase. Otherwise it is a personal backup, needsKeystoreRefresh=true.
     */
    data class ParsedConfig(
        val entity: ConfigEntity,
        val p12Bytes: ByteArray?,
    )

    fun parse(zipBytes: ByteArray): List<ParsedConfig> {
        // First pass: read the zip into a name -> bytes map to avoid any
        // assumption about entry order.
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
            ?: error("invalid zip: no $CONFIGS_JSON")
        val root = JSONObject(String(configsJson, Charsets.UTF_8))
        val schema = root.getInt("schema")
        require(schema == SCHEMA_VERSION) {
            "unsupported bundle schema $schema (expected $SCHEMA_VERSION)"
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
            ?: error("incomplete zip: $certPemFile missing")
        val caPem = files[caPemFile]
            ?: error("incomplete zip: $caPemFile missing")
        // Optional field for IT deployment bundles.
        val p12Bytes: ByteArray? = if (o.has("p12File") && !o.isNull("p12File")) {
            val p12File = o.getString("p12File")
            files[p12File] ?: error("incomplete zip: $p12File missing")
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
            // The bundle's alias is ignored: ConfigRepository.importZip generates
            // a fresh one (a bundle must never be able to target an existing key).
            keystoreAlias = "",
            mode = ProxyMode.valueOf(o.getString("mode")),
            syntheticIp = if (o.isNull("syntheticIp")) null else o.getString("syntheticIp"),
            syntheticPort = if (o.isNull("syntheticPort")) null else o.getInt("syntheticPort"),
            loopbackPort = if (o.isNull("loopbackPort")) null else o.getInt("loopbackPort"),
            securityLevel = KeySecurityLevel.UNKNOWN,
            createdAtEpochMs = System.currentTimeMillis(),
            // With .p12: enabled right away once the Keystore import succeeds.
            // Without .p12: needsKeystoreRefresh=true, disabled.
            enabled = p12Bytes != null,
            needsKeystoreRefresh = p12Bytes == null,
            pathToken = if (o.has("pathToken") && !o.isNull("pathToken"))
                o.getString("pathToken").takeIf { it.isNotBlank() }
            else null,
            extraCanonicalHosts = parseExtraCanonicalHosts(o),
        )
        return ParsedConfig(entity, p12Bytes)
    }

    /** Optional field: JSON array (export format) or comma-separated string. */
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
