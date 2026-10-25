package com.douxev.mtls_bridge.remote

import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.util.Base64
import android.util.Log
import com.douxev.mtls_bridge.BuildConfig
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.R
import com.douxev.mtls_bridge.data.ConfigEntity
import com.douxev.mtls_bridge.data.NewConfigRequest
import com.douxev.mtls_bridge.data.PathTokenGen
import com.douxev.mtls_bridge.data.ProxyMode
import com.douxev.mtls_bridge.data.SyntheticEndpoints
import com.douxev.mtls_bridge.data.clientUrl
import com.douxev.mtls_bridge.runtime.InstalledApps
import com.douxev.mtls_bridge.service.ProxyLauncher
import com.douxev.mtls_bridge.ui.tv.isTelevision
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlinx.coroutines.flow.first
import org.json.JSONArray
import org.json.JSONObject

/**
 * `/api/...` routes of the admin console, once the session is authenticated.
 * Each handler relies on [com.douxev.mtls_bridge.data.ConfigRepository],
 * exactly like the local UI: the coordinator starts/stops the proxies in
 * response to database changes.
 *
 * Files (.p12, CA, bundle) arrive base64-encoded in the JSON.
 */
internal class RemoteAdminApi(
    private val app: MtlsApplication,
    /** Describes an action performed remotely, shown on the device screen. */
    private val onActivity: (String) -> Unit,
) {
    private val repo get() = app.configRepo
    private val pm get() = app.packageManager

    suspend fun handle(req: HttpRequest, peer: String): HttpResponse {
        val seg = req.path.removePrefix("/api/").trim('/').split('/').filter { it.isNotEmpty() }
        return try {
            route(req, seg, peer)
        } catch (e: HttpException) {
            HttpResponse.error(e.status, e.message ?: "error")
        } catch (e: IllegalArgumentException) {
            // `require(...)` in the repository: readable message for the user.
            HttpResponse.error(400, e.message ?: "invalid request")
        } catch (e: IllegalStateException) {
            // `error(...)` in the repository (duplicate, config not found...).
            HttpResponse.error(400, e.message ?: "operation refused")
        } catch (e: Exception) {
            Log.w(TAG, "api ${req.method} ${req.path} failed", e)
            HttpResponse.error(500, e.message ?: e::class.java.simpleName)
        }
    }

    private suspend fun route(req: HttpRequest, seg: List<String>, peer: String): HttpResponse {
        val m = req.method
        return when {
            m == "GET" && seg == listOf("state") -> state()
            m == "GET" && seg == listOf("apps") -> apps()
            m == "POST" && seg == listOf("configs") -> create(req, peer)
            seg.size == 2 && seg[0] == "configs" && m == "PUT" -> update(seg[1], req, peer)
            seg.size == 2 && seg[0] == "configs" && m == "DELETE" -> delete(seg[1], peer)
            seg.size == 3 && seg[0] == "configs" && seg[2] == "enabled" && m == "POST" ->
                setEnabled(seg[1], req, peer)
            seg.size == 3 && seg[0] == "configs" && seg[2] == "key" && m == "POST" ->
                reimportKey(seg[1], req, peer)
            seg.size == 3 && seg[0] == "configs" && seg[2] == "events" && m == "GET" ->
                events(seg[1])
            m == "POST" && seg == listOf("bundle", "preview") -> bundlePreview(req)
            m == "POST" && seg == listOf("bundle", "import") -> bundleImport(req, peer)
            m == "POST" && seg == listOf("bundle", "export") -> bundleExport(req, peer)
            m == "POST" && seg == listOf("vpn") -> vpn(req, peer)
            else -> HttpResponse.error(404, "unknown route")
        }
    }

    // ----- Reads ------------------------------------------------------------

    private suspend fun state(): HttpResponse {
        val configs = repo.observeAll().first()
        val arr = JSONArray()
        configs.forEach { arr.put(dto(it)) }
        return HttpResponse.ok(
            JSONObject()
                .put("device", deviceName())
                .put("isTv", app.isTelevision())
                .put("version", BuildConfig.VERSION_NAME)
                .put("vpnRunning", app.vpnRunning.value)
                .put("vpnConsentNeeded", VpnService.prepare(app) != null)
                .put("configs", arr)
        )
    }

    private fun apps(): HttpResponse {
        val arr = JSONArray()
        InstalledApps.launchable(pm, app.packageName).forEach {
            arr.put(JSONObject().put("packageName", it.packageName).put("label", it.label))
        }
        return HttpResponse.ok(JSONObject().put("apps", arr))
    }

    private suspend fun events(id: String): HttpResponse {
        requireConfig(id)
        val arr = JSONArray()
        app.db.auditDao().observeRecent(id, 100).first().forEach {
            arr.put(
                JSONObject()
                    .put("timestampMs", it.timestampMs)
                    .put("type", it.eventType)
                    .put("details", it.details)
            )
        }
        return HttpResponse.ok(JSONObject().put("events", arr))
    }

    // ----- Writes -----------------------------------------------------------

    private suspend fun create(req: HttpRequest, peer: String): HttpResponse {
        val o = req.json()
        val mode = parseMode(o)
        val passphrase = o.optString("p12Passphrase").toCharArray()
        // Synthetic IP/port left empty: first free pair (a duplicate would make
        // the whole VPN fail).
        val synthetic = if (mode == ProxyMode.VPN && o.optNullableString("syntheticIp") == null) {
            repo.allocateSyntheticEndpoint()
        } else null
        val created = repo.create(
            NewConfigRequest(
                displayName = o.optString("displayName").trim(),
                targetPackage = o.optString("targetPackage").trim(),
                upstreamHost = o.optString("upstreamHost").trim(),
                upstreamPort = o.optInt("upstreamPort", 443),
                sni = o.optNullableString("sni"),
                caPem = ensurePem(decodeFile(o, "caBase64", "pinned CA")),
                mode = mode,
                syntheticIp = (synthetic?.first ?: o.optNullableString("syntheticIp"))
                    .takeIf { mode == ProxyMode.VPN },
                syntheticPort = (synthetic?.second ?: o.optNullableInt("syntheticPort"))
                    .takeIf { mode == ProxyMode.VPN },
                loopbackPort = if (mode == ProxyMode.LOOPBACK) {
                    o.optNullableInt("loopbackPort") ?: (10001..32767).random()
                } else null,
                // Token enabled by default: the only effective loopback
                // isolation (the proxy sets a cookie for webviews).
                pathToken = if (mode == ProxyMode.LOOPBACK && o.optBoolean("pathTokenEnabled", true)) {
                    o.optNullableString("pathToken") ?: PathTokenGen.generate()
                } else null,
                extraCanonicalHosts = o.optNullableString("extraCanonicalHosts")
                    .takeIf { mode == ProxyMode.LOOPBACK },
                p12Bytes = decodeFile(o, "p12Base64", ".p12"),
                p12Passphrase = passphrase,
            )
        )
        onActivity(app.getString(R.string.svc_activity_created, created.displayName, peer))
        return HttpResponse.ok(JSONObject().put("config", dto(created)))
    }

    private suspend fun update(id: String, req: HttpRequest, peer: String): HttpResponse {
        val existing = requireConfig(id)
        val o = req.json()
        val mode = parseMode(o)
        // Missing field: the current state is kept (like the other fields), no
        // silent disabling of the isolation.
        val tokenEnabled = mode == ProxyMode.LOOPBACK &&
            o.optBoolean("pathTokenEnabled", existing.pathToken != null)
        val token = when {
            !tokenEnabled -> null
            o.optBoolean("regenerateToken") -> PathTokenGen.generate()
            else -> existing.pathToken ?: PathTokenGen.generate()
        }
        val synthetic = if (mode == ProxyMode.VPN &&
            o.optNullableString("syntheticIp") == null && existing.syntheticIp == null
        ) repo.allocateSyntheticEndpoint(excludeId = id) else null
        repo.updateMetadata(
            id = id,
            displayName = o.optString("displayName", existing.displayName).trim(),
            targetPackage = o.optString("targetPackage", existing.targetPackage).trim(),
            upstreamHost = o.optString("upstreamHost", existing.upstreamHost).trim(),
            upstreamPort = o.optInt("upstreamPort", existing.upstreamPort),
            sni = if (o.has("sni")) o.optNullableString("sni") else existing.sni,
            mode = mode,
            syntheticIp = synthetic?.first ?: o.optNullableString("syntheticIp") ?: existing.syntheticIp,
            syntheticPort = synthetic?.second ?: o.optNullableInt("syntheticPort")
                ?: existing.syntheticPort ?: SyntheticEndpoints.DEFAULT_PORT,
            loopbackPort = o.optNullableInt("loopbackPort") ?: existing.loopbackPort
                ?: (10001..32767).random(),
            pathToken = token,
            extraCanonicalHosts = if (o.has("extraCanonicalHosts")) {
                o.optNullableString("extraCanonicalHosts")
            } else existing.extraCanonicalHosts,
        )
        val updated = requireConfig(id)
        onActivity(app.getString(R.string.svc_activity_updated, updated.displayName, peer))
        return HttpResponse.ok(JSONObject().put("config", dto(updated)))
    }

    private suspend fun delete(id: String, peer: String): HttpResponse {
        val cfg = requireConfig(id)
        repo.delete(id)
        onActivity(app.getString(R.string.svc_activity_deleted, cfg.displayName, peer))
        return HttpResponse.ok()
    }

    private suspend fun setEnabled(id: String, req: HttpRequest, peer: String): HttpResponse {
        val cfg = requireConfig(id)
        val enabled = req.json().optBoolean("enabled")
        if (enabled && cfg.needsKeystoreRefresh) {
            throw HttpException(409, "missing key: provide the .p12 of this config first")
        }
        repo.setEnabled(id, enabled)
        onActivity(
            app.getString(
                if (enabled) R.string.svc_activity_enabled else R.string.svc_activity_disabled,
                cfg.displayName,
                peer,
            )
        )
        return HttpResponse.ok()
    }

    private suspend fun reimportKey(id: String, req: HttpRequest, peer: String): HttpResponse {
        val cfg = requireConfig(id)
        val o = req.json()
        repo.reimportKey(id, decodeFile(o, "p12Base64", ".p12"), o.optString("p12Passphrase").toCharArray())
        onActivity(app.getString(R.string.svc_activity_key_imported, cfg.displayName, peer))
        return HttpResponse.ok(JSONObject().put("config", dto(requireConfig(id))))
    }

    private suspend fun bundlePreview(req: HttpRequest): HttpResponse {
        val p = repo.peekZip(decodeFile(req.json(), "zipBase64", "bundle"))
        return HttpResponse.ok(
            JSONObject()
                .put("totalConfigs", p.totalConfigs)
                .put("withKey", p.withKey)
                .put("withoutKey", p.withoutKey)
                .put("needsPassphrase", p.needsPassphrase)
        )
    }

    private suspend fun bundleImport(req: HttpRequest, peer: String): HttpResponse {
        val o = req.json()
        val zip = decodeFile(o, "zipBase64", "bundle")
        val pass = o.optNullableString("passphrase")?.toCharArray()
        val r = repo.importZip(zip, pass)
        onActivity(
            app.getString(
                R.string.svc_activity_bundle_imported,
                peer,
                r.importedWithKey,
                r.importedWithoutKey,
                r.skipped,
            )
        )
        return HttpResponse.ok(
            JSONObject()
                .put("importedWithKey", r.importedWithKey)
                .put("importedWithoutKey", r.importedWithoutKey)
                .put("skipped", r.skipped)
        )
    }

    private suspend fun bundleExport(req: HttpRequest, peer: String): HttpResponse {
        val ids = req.json().optJSONArray("ids")?.let { a ->
            (0 until a.length()).map { a.getString(it) }.toSet()
        }
        val zip = repo.exportZip(ids)
        onActivity(
            if (ids == null) app.getString(R.string.svc_activity_export_all, peer)
            else app.getString(R.string.svc_activity_export_some, ids.size, peer)
        )
        return HttpResponse(
            200,
            "application/zip",
            zip,
            mapOf("Content-Disposition" to "attachment; filename=\"mtls_bridge-backup.zip\""),
        )
    }

    private fun vpn(req: HttpRequest, peer: String): HttpResponse {
        val running = req.json().optBoolean("running")
        if (running) {
            if (VpnService.prepare(app) != null) {
                throw HttpException(
                    409,
                    "Android must authorize the VPN first: turn it on once from the device",
                )
            }
            ProxyLauncher.startVpnGlobal(app)
        } else {
            ProxyLauncher.stopVpn(app)
        }
        onActivity(
            app.getString(
                if (running) R.string.svc_activity_vpn_started else R.string.svc_activity_vpn_stopped,
                peer,
            )
        )
        return HttpResponse.ok()
    }

    // ----- Helpers ----------------------------------------------------------

    private suspend fun requireConfig(id: String): ConfigEntity =
        repo.byId(id) ?: throw HttpException(404, "config not found")

    private fun dto(c: ConfigEntity): JSONObject {
        val cert = runCatching {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(c.certChainPem)) as X509Certificate
        }.getOrNull()
        return JSONObject()
            .put("id", c.id)
            .put("displayName", c.displayName)
            .put("targetPackage", c.targetPackage)
            .put("targetLabel", InstalledApps.label(pm, c.targetPackage) ?: JSONObject.NULL)
            .put("upstreamHost", c.upstreamHost)
            .put("upstreamPort", c.upstreamPort)
            .put("sni", c.sni ?: JSONObject.NULL)
            .put("mode", c.mode.name)
            .put("syntheticIp", c.syntheticIp ?: JSONObject.NULL)
            .put("syntheticPort", c.syntheticPort ?: JSONObject.NULL)
            .put("loopbackPort", c.loopbackPort ?: JSONObject.NULL)
            .put("enabled", c.enabled)
            .put("needsKeystoreRefresh", c.needsKeystoreRefresh)
            .put("securityLevel", c.securityLevel.name)
            .put("pathToken", c.pathToken ?: JSONObject.NULL)
            .put("extraCanonicalHosts", c.extraCanonicalHosts ?: JSONObject.NULL)
            .put("clientUrl", c.clientUrl() ?: JSONObject.NULL)
            .put("certSubject", cert?.subjectX500Principal?.name ?: JSONObject.NULL)
            .put("certNotAfterMs", cert?.notAfter?.time ?: JSONObject.NULL)
    }

    private fun parseMode(o: JSONObject): ProxyMode =
        when (o.optString("mode", "LOOPBACK").uppercase()) {
            "VPN" -> ProxyMode.VPN
            "LOOPBACK" -> ProxyMode.LOOPBACK
            else -> throw HttpException(400, "unknown mode")
        }

    private fun decodeFile(o: JSONObject, key: String, what: String): ByteArray {
        val b64 = o.optString(key)
        if (b64.isBlank()) throw HttpException(400, "missing file: $what")
        return try {
            Base64.decode(b64, Base64.DEFAULT)
        } catch (_: IllegalArgumentException) {
            throw HttpException(400, "unreadable file: $what")
        }
    }

    /**
     * The Rust core expects PEM. A DER .crt/.cer is converted here rather than
     * failing silently when the proxy starts.
     */
    private fun ensurePem(bytes: ByteArray): ByteArray {
        val head = String(bytes, 0, minOf(bytes.size, 64), Charsets.US_ASCII)
        if (head.contains("-----BEGIN")) return bytes
        val certs = try {
            CertificateFactory.getInstance("X.509").generateCertificates(ByteArrayInputStream(bytes))
        } catch (_: Exception) {
            throw HttpException(400, "unreadable CA: neither PEM nor DER")
        }
        if (certs.isEmpty()) throw HttpException(400, "empty CA")
        return certs.joinToString("\n") { cert ->
            val b64 = Base64.encodeToString(cert.encoded, Base64.NO_WRAP).chunked(64).joinToString("\n")
            "-----BEGIN CERTIFICATE-----\n$b64\n-----END CERTIFICATE-----"
        }.toByteArray(Charsets.US_ASCII)
    }

    private fun deviceName(): String =
        Settings.Global.getString(app.contentResolver, Settings.Global.DEVICE_NAME)
            ?.takeIf { it.isNotBlank() }
            ?: "${Build.MANUFACTURER} ${Build.MODEL}"

    private fun JSONObject.optNullableString(key: String): String? =
        if (!has(key) || isNull(key)) null else optString(key).trim().takeIf { it.isNotEmpty() }

    private fun JSONObject.optNullableInt(key: String): Int? =
        if (!has(key) || isNull(key)) null
        else when (val v = opt(key)) {
            is Number -> v.toInt()
            is String -> v.trim().toIntOrNull()
            else -> null
        }

    private companion object {
        const val TAG = "mtls_bridge.remote"
    }
}
