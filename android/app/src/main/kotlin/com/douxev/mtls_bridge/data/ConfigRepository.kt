package com.douxev.mtls_bridge.data

import com.douxev.mtls_bridge.keystore.P12Importer
import java.security.KeyStore
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext

data class NewConfigRequest(
    val displayName: String,
    val targetPackage: String,
    val upstreamHost: String,
    val upstreamPort: Int,
    val sni: String?,
    val caPem: ByteArray,
    val mode: ProxyMode,
    /** VPN only. Synthetic TEST-NET address (192.0.2.X) assigned by the UI. */
    val syntheticIp: String? = null,
    val syntheticPort: Int? = null,
    /** Loopback only. 0 = ephemeral port, chosen at start_loopback. */
    val loopbackPort: Int? = null,
    /**
     * Loopback only. URL-safe token inserted into the HTTP path to isolate
     * the config from other apps. `null` = no check.
     */
    val pathToken: String? = null,
    /** Loopback only. Free-form input, normalized by [CanonicalHosts]. */
    val extraCanonicalHosts: String? = null,
    /** The user's .p12 + passphrase entered in the UI. */
    val p12Bytes: ByteArray,
    val p12Passphrase: CharArray,
)

/**
 * Synthetic IP range for VPN mode: TEST-NET-1 (RFC 5737). `.254` is the
 * address of the tun itself, `.0` and `.255` are network/broadcast.
 */
object SyntheticEndpoints {
    const val TUN_NET = "192.0.2.0"
    const val TUN_LOCAL_IP = "192.0.2.254"
    const val TUN_PREFIX = 24
    const val DEFAULT_PORT = 5001
    private const val PREFIX = "192.0.2."
    private val HOSTS = 1..253
    private val IP_RE = Regex("""^192\.0\.2\.(0|[1-9][0-9]{0,2})$""")

    fun isValidIp(ip: String?): Boolean {
        val host = ip?.trim()?.let { IP_RE.find(it) }?.groupValues?.get(1)?.toInt()
        return host != null && host in HOSTS
    }

    /**
     * First free pair: a distinct IP per config while any remain (readable
     * URL), then other ports on the IPs already taken.
     */
    fun allocate(taken: Collection<Pair<String, Int>>): Pair<String, Int> {
        val usedIps = taken.map { it.first }.toSet()
        HOSTS.map { "$PREFIX$it" }.firstOrNull { it !in usedIps }
            ?.let { return it to DEFAULT_PORT }
        val used = taken.toSet()
        for (port in DEFAULT_PORT + 1..65535) {
            HOSTS.map { "$PREFIX$it" to port }.firstOrNull { it !in used }?.let { return it }
        }
        error("no free synthetic IP/port left")
    }
}

/**
 * Fixed ports for loopback mode. Drawn from 10001..32767 as when creating a
 * config: above the common "registered" ports, below the Linux ephemeral
 * range (32768+).
 */
object LoopbackPorts {
    private val RANDOM_RANGE = 10001..32767

    /** Random port from the range, outside [taken]. */
    fun allocate(taken: Set<Int>): Int {
        repeat(64) {
            val port = RANDOM_RANGE.random()
            if (port !in taken) return port
        }
        return RANDOM_RANGE.firstOrNull { it !in taken } ?: error("no free loopback port left")
    }
}

class ConfigRepository(
    private val dao: ConfigDao,
    private val p12Importer: P12Importer = P12Importer(),
) {

    fun observeAll(): Flow<List<ConfigEntity>> = dao.observeAll()

    suspend fun byId(id: String): ConfigEntity? = dao.byId(id)

    /**
     * Creates a config: imports the .p12 into the Keystore, then persists the
     * metadata in the DB. If the DB write fails after the import, the Keystore
     * entry is rolled back. Main-safe: PKCS#12 parsing and Keystore operations
     * run on Dispatchers.IO.
     */
    suspend fun create(req: NewConfigRequest): ConfigEntity = withContext(Dispatchers.IO) {
        try {
            insertNew(req)
        } finally {
            // Wipe the passphrase from RAM as soon as it is no longer needed.
            req.p12Passphrase.fill('\u0000')
        }
    }

    private suspend fun insertNew(req: NewConfigRequest): ConfigEntity {
        require(req.displayName.isNotBlank()) { "name is required" }
        require(req.targetPackage.isNotBlank()) {
            "target app is required: select it from the dropdown"
        }
        val sanitizedHost = sanitizeHost(req.upstreamHost)
        require(sanitizedHost.isNotBlank()) { "host is required" }
        require(req.upstreamPort in 1..65535) { "port out of range" }
        require(req.caPem.isNotEmpty()) { "CA pinning is required (MVP)" }
        // Explicitly reject a second config for the same app: a readable error
        // message rather than a raw SQLiteConstraintException.
        if (dao.findByTargetPackage(req.targetPackage) != null) {
            error("a config already exists for ${req.targetPackage}: edit or delete it first")
        }
        when (req.mode) {
            ProxyMode.VPN -> requireFreeSyntheticEndpoint(null, req.syntheticIp, req.syntheticPort)
            ProxyMode.LOOPBACK -> {
                require(req.loopbackPort != null && req.loopbackPort in 0..65535) {
                    "invalid loopback port"
                }
            }
        }

        val id = UUID.randomUUID().toString()
        val keystoreAlias = "mtls_bridge-$id"

        val imported = p12Importer.import(req.p12Bytes, req.p12Passphrase, keystoreAlias)

        val entity = ConfigEntity(
            id = id,
            displayName = req.displayName,
            targetPackage = req.targetPackage,
            upstreamHost = sanitizedHost,
            upstreamPort = req.upstreamPort,
            sni = req.sni,
            caPem = req.caPem,
            certChainPem = imported.certChainPem,
            keystoreAlias = keystoreAlias,
            mode = req.mode,
            syntheticIp = req.syntheticIp?.trim(),
            syntheticPort = req.syntheticPort,
            loopbackPort = req.loopbackPort,
            securityLevel = imported.securityLevel,
            createdAtEpochMs = System.currentTimeMillis(),
            // Loopback only: the token is persisted as is. VPN: null.
            pathToken = req.pathToken?.takeIf { req.mode == ProxyMode.LOOPBACK },
            extraCanonicalHosts = CanonicalHosts.normalize(req.extraCanonicalHosts)
                ?.takeIf { req.mode == ProxyMode.LOOPBACK },
        )
        try {
            dao.insert(entity)
        } catch (t: Throwable) {
            // Keystore rollback: the imported key must go away if the matching
            // DB metadata could not be persisted.
            deleteKeystoreEntry(keystoreAlias)
            throw t
        }
        return entity
    }

    /**
     * Updates the editable fields of a config without touching the keystore.
     * To rotate the cert: delete + recreate (the cert is tied to the Keystore
     * alias; this avoids the complexity of a live re-import).
     */
    suspend fun updateMetadata(
        id: String,
        displayName: String,
        targetPackage: String,
        upstreamHost: String,
        upstreamPort: Int,
        sni: String?,
        mode: ProxyMode,
        syntheticIp: String?,
        syntheticPort: Int?,
        loopbackPort: Int?,
        pathToken: String?,
        extraCanonicalHosts: String? = null,
    ) {
        require(displayName.isNotBlank()) { "name is required" }
        require(targetPackage.isNotBlank()) { "target app is required" }
        val sanitizedHost = sanitizeHost(upstreamHost)
        require(sanitizedHost.isNotBlank()) { "host is required" }
        require(upstreamPort in 1..65535) { "port out of range" }
        when (mode) {
            ProxyMode.VPN -> requireFreeSyntheticEndpoint(id, syntheticIp, syntheticPort)
            ProxyMode.LOOPBACK -> {
                require(loopbackPort != null && loopbackPort in 0..65535) {
                    "invalid loopback port"
                }
            }
        }
        val existing = dao.byId(id) ?: error("config $id not found")
        // Same on update: when targetPackage changes, reject it if already
        // taken by ANOTHER config (its own does not count as a conflict).
        if (existing.targetPackage != targetPackage) {
            dao.findByTargetPackage(targetPackage)?.let {
                error("$targetPackage is already used by config '${it.displayName}'")
            }
        }
        dao.update(
            existing.copy(
                displayName = displayName,
                targetPackage = targetPackage,
                upstreamHost = sanitizedHost,
                upstreamPort = upstreamPort,
                sni = sni,
                mode = mode,
                syntheticIp = if (mode == ProxyMode.VPN) syntheticIp?.trim() else null,
                syntheticPort = if (mode == ProxyMode.VPN) syntheticPort else null,
                loopbackPort = if (mode == ProxyMode.LOOPBACK) loopbackPort else null,
                pathToken = if (mode == ProxyMode.LOOPBACK) pathToken else null,
                extraCanonicalHosts = if (mode == ProxyMode.LOOPBACK)
                    CanonicalHosts.normalize(extraCanonicalHosts)
                else null,
            )
        )
    }

    /**
     * Free synthetic IP/port pair for a VPN config. All routes share a single
     * tun: a duplicate makes the whole VPN fail in the core.
     */
    suspend fun allocateSyntheticEndpoint(excludeId: String? = null): Pair<String, Int> =
        SyntheticEndpoints.allocate(takenSyntheticEndpoints(excludeId))

    private suspend fun takenSyntheticEndpoints(excludeId: String?): List<Pair<String, Int>> =
        dao.all().mapNotNull { c ->
            if (c.id == excludeId || c.mode != ProxyMode.VPN) return@mapNotNull null
            val ip = c.syntheticIp ?: return@mapNotNull null
            val port = c.syntheticPort ?: return@mapNotNull null
            ip to port
        }

    /** Ports listened on by loopback configs, active or not. */
    private suspend fun takenLoopbackPorts(): Set<Int> =
        dao.all().mapNotNullTo(HashSet()) { c ->
            c.loopbackPort.takeIf { c.mode == ProxyMode.LOOPBACK }
        }

    private suspend fun requireFreeSyntheticEndpoint(selfId: String?, ip: String?, port: Int?) {
        require(SyntheticEndpoints.isValidIp(ip)) {
            "invalid synthetic IP: expected 192.0.2.1 to 192.0.2.253"
        }
        require(port != null && port in 1..65535) { "invalid synthetic port" }
        val endpoint = ip!!.trim() to port
        if (endpoint in takenSyntheticEndpoints(selfId)) {
            error("${endpoint.first}:${endpoint.second} is already used by another VPN config")
        }
    }

    /**
     * Tolerates inputs like "https://host", "host/", "host:443": only the DNS
     * name (or IP) is kept, which becomes the SNI and the TCP target.
     */
    private fun sanitizeHost(input: String): String {
        var h = input.trim()
        listOf("https://", "http://").forEach { p ->
            if (h.startsWith(p, ignoreCase = true)) h = h.substring(p.length)
        }
        h = h.substringBefore('/')
        h = h.substringBefore(':') // port typed by accident: drop it
        return h
    }

    suspend fun setEnabled(id: String, enabled: Boolean) {
        dao.setEnabled(id, enabled)
    }

    /** "Stop" button of the notification: turns off every loopback config. */
    suspend fun disableAllLoopback() {
        dao.disableAllOfMode(ProxyMode.LOOPBACK)
    }

    /** Zip export of the selected configs (without the private key). */
    suspend fun exportZip(ids: Set<String>? = null): ByteArray {
        val all = dao.all()
        val subset = if (ids == null) all else all.filter { it.id in ids }
        return withContext(Dispatchers.Default) { ConfigBackup.export(subset) }
    }

    data class ImportSummary(
        /** Configs imported with their .p12: immediately operational. */
        val importedWithKey: Int,
        /** Configs imported without .p12: flagged needsKeystoreRefresh. */
        val importedWithoutKey: Int,
        /** Skipped configs (known id / targetPackage already taken / error). */
        val skipped: Int,
    )

    /**
     * Pre-inspects a bundle to find out whether it contains .p12 files
     * (deployment), so the UI can ask for the passphrase BEFORE the import.
     */
    suspend fun peekZip(zipBytes: ByteArray): BundlePreview {
        val parsed = withContext(Dispatchers.Default) { ConfigBackup.parse(zipBytes) }
        return BundlePreview(
            totalConfigs = parsed.size,
            withKey = parsed.count { it.p12Bytes != null },
            withoutKey = parsed.count { it.p12Bytes == null },
        )
    }

    data class BundlePreview(
        val totalConfigs: Int,
        val withKey: Int,
        val withoutKey: Int,
    ) {
        val needsPassphrase: Boolean get() = withKey > 0
    }

    /**
     * Imports a bundle zip. If some configs carry an inline .p12, the
     * `p12Passphrase` is required (shared by every .p12 in the bundle, a
     * convention for the IT deployment case).
     *
     * For each config:
     * - If the id already exists: skip (no silent overwrite).
     * - If the targetPackage is already taken: skip.
     * - The bundle's Keystore alias is ignored: a fresh one is generated,
     *   otherwise a bundle could overwrite the key of an existing config.
     * - Invalid or already taken synthetic IP/port: reallocated.
     * - Loopback port outside 1..65535 (including `0` "ephemeral" and missing)
     *   or already taken by another loopback config: drawn from 10001..32767.
     * - Otherwise: if a .p12 is present and a passphrase was supplied, the key
     *   is imported into the Keystore (after the cert check) and the config is
     *   inserted with enabled=true; else needsKeystoreRefresh=true.
     */
    suspend fun importZip(
        zipBytes: ByteArray,
        p12Passphrase: CharArray? = null,
    ): ImportSummary = withContext(Dispatchers.IO) {
        try {
            importParsed(ConfigBackup.parse(zipBytes), p12Passphrase)
        } finally {
            // Wipe the passphrase from RAM as soon as it is no longer needed.
            p12Passphrase?.fill('\u0000')
        }
    }

    private suspend fun importParsed(
        parsed: List<ConfigBackup.ParsedConfig>,
        p12Passphrase: CharArray?,
    ): ImportSummary {
        var withKey = 0
        var withoutKey = 0
        var skipped = 0
        for (pc in parsed) {
            val bundled = pc.entity
            if (dao.byId(bundled.id) != null) { skipped++; continue }
            if (dao.findByTargetPackage(bundled.targetPackage) != null) { skipped++; continue }

            var cfg = bundled.copy(keystoreAlias = newKeystoreAlias())
            if (cfg.mode == ProxyMode.VPN) {
                val ip = cfg.syntheticIp?.trim()
                val port = cfg.syntheticPort
                val taken = takenSyntheticEndpoints(null)
                if (!SyntheticEndpoints.isValidIp(ip) || port == null || port !in 1..65535 ||
                    (ip!! to port) in taken
                ) {
                    val (newIp, newPort) = SyntheticEndpoints.allocate(taken)
                    cfg = cfg.copy(syntheticIp = newIp, syntheticPort = newPort)
                }
            } else if (cfg.mode == ProxyMode.LOOPBACK) {
                // A taken port makes the bind of one of the two configs fail;
                // 70000 would be truncated at startup (toUShort); 0 would change
                // the URL to copy into the target app on every start.
                val port = cfg.loopbackPort
                val taken = takenLoopbackPorts()
                if (port == null || port !in 1..65535 || port in taken) {
                    cfg = cfg.copy(loopbackPort = LoopbackPorts.allocate(taken))
                }
            }

            if (pc.p12Bytes != null && p12Passphrase != null) {
                val imported = try {
                    // The bundle cert is checked BEFORE the Keystore write: a
                    // .p12 that does not match leaves no key behind.
                    p12Importer.import(
                        pc.p12Bytes, p12Passphrase, cfg.keystoreAlias,
                        expectedLeafCertPem = cfg.certChainPem,
                    )
                } catch (_: Throwable) {
                    deleteKeystoreEntry(cfg.keystoreAlias)
                    skipped++
                    continue
                }
                try {
                    dao.insert(
                        cfg.copy(
                            securityLevel = imported.securityLevel,
                            needsKeystoreRefresh = false,
                            enabled = true,
                        )
                    )
                    withKey++
                } catch (_: Throwable) {
                    deleteKeystoreEntry(cfg.keystoreAlias)
                    skipped++
                }
            } else {
                // No .p12 (backup) OR no passphrase supplied: metadata-only
                // import, the user will have to provide the key afterwards.
                try {
                    dao.insert(
                        cfg.copy(
                            needsKeystoreRefresh = true,
                            enabled = false,
                        )
                    )
                    withoutKey++
                } catch (_: Throwable) {
                    skipped++
                }
            }
        }
        return ImportSummary(withKey, withoutKey, skipped)
    }

    /**
     * Re-imports the .p12 key for an existing config (after an import from a
     * file). Reuses the existing Keystore alias; on success, clears
     * needsKeystoreRefresh and updates the attestation level actually obtained
     * on this device.
     */
    suspend fun reimportKey(
        id: String,
        p12Bytes: ByteArray,
        p12Passphrase: CharArray,
    ): Unit = withContext(Dispatchers.IO) {
        try {
            val cfg = dao.byId(id) ?: error("config $id not found")
            // Consistency check BEFORE writing to the Keystore: the .p12 cert
            // must be the one stored in the DB (otherwise it is a different
            // cert, rejected without touching the alias).
            val imported = p12Importer.import(
                p12Bytes, p12Passphrase, cfg.keystoreAlias,
                expectedLeafCertPem = cfg.certChainPem,
            )
            dao.update(
                cfg.copy(
                    securityLevel = imported.securityLevel,
                    needsKeystoreRefresh = false,
                )
            )
        } finally {
            p12Passphrase.fill('\u0000')
        }
    }

    suspend fun delete(id: String) {
        val cfg = dao.byId(id) ?: return
        dao.delete(id)
        withContext(Dispatchers.IO) { deleteKeystoreEntry(cfg.keystoreAlias) }
    }

    private fun newKeystoreAlias() = "mtls_bridge-${UUID.randomUUID()}"

    private fun deleteKeystoreEntry(alias: String) {
        runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(alias)
        }
    }
}
