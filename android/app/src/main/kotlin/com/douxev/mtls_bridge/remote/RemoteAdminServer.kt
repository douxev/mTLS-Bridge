package com.douxev.mtls_bridge.remote

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Base64
import android.util.Log
import com.douxev.mtls_bridge.MtlsApplication
import com.douxev.mtls_bridge.R
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import java.net.BindException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.SocketException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLException
import javax.net.ssl.SSLServerSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import org.json.JSONObject

/**
 * Admin console on the local network: serves a web page (HTTPS) used to
 * configure the app from the browser of a computer or a smartphone. Essential
 * on Android TV / Google TV, where typing a host, a .p12 and its passphrase
 * with the remote control is painful (and where there is often no file
 * picker).
 *
 * Security:
 * - only runs while the "Remote configuration" screen is open, and stops by
 *   itself after [IDLE_TIMEOUT_MS] without a request;
 * - HTTPS (self-signed cert, key in the Keystore, fingerprint displayed);
 * - pairing with a 6-digit PIN shown on the device screen, single use,
 *   renewed after [MAX_PIN_ATTEMPTS] failures (+ lockout);
 * - session = random token sent as `Authorization: Bearer` (no cookie, so no
 *   CSRF possible from another page).
 */
class RemoteAdminServer(private val app: MtlsApplication) {

    data class Status(
        val running: Boolean = false,
        val starting: Boolean = false,
        /** `https://ip:port/` for each local network interface. */
        val urls: List<String> = emptyList(),
        val pin: String = "",
        val fingerprint: String = "",
        val sessions: Int = 0,
        val lastActivity: String? = null,
        val error: String? = null,
    ) {
        /** QR code content: the PIN travels in the fragment, never sent to the server. */
        val qrPayload: String? get() = urls.firstOrNull()?.let { "$it#pin=$pin" }
    }

    private val _status = MutableStateFlow(Status())
    val status: StateFlow<Status> = _status.asStateFlow()

    private val rng = SecureRandom()
    private val sessions = ConcurrentHashMap<String, Long>() // token -> last use (ms)
    private val api = RemoteAdminApi(app) { msg -> _status.update { it.copy(lastActivity = msg) } }
    private val connections = Semaphore(MAX_CONNECTIONS)

    private var scope: CoroutineScope? = null
    @Volatile private var serverSocket: SSLServerSocket? = null
    @Volatile private var pin: String = ""
    @Volatile private var failedAttempts = 0
    @Volatile private var lockedUntilMs = 0L
    @Volatile private var lastRequestMs = 0L

    @Synchronized
    fun start() {
        if (scope != null) return
        val s = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope = s
        _status.value = Status(starting = true)
        s.launch {
            try {
                val tls = RemoteTls.material()
                val ss = bind(tls)
                try {
                    // stop() may have run during the bind: do not leave an
                    // orphan listening socket behind.
                    if (!isActive) return@launch
                    serverSocket = ss
                    lastRequestMs = System.currentTimeMillis()
                    rotatePin()
                    _status.value = Status(
                        running = true,
                        urls = localUrls(ss.localPort),
                        pin = pin,
                        fingerprint = tls.fingerprint,
                    )
                    launch { idleWatchdog() }
                    acceptLoop(s, ss)
                } finally {
                    runCatching { ss.close() }
                }
            } catch (t: Throwable) {
                Log.e(TAG, "cannot start the console", t)
                _status.value = Status(
                    error = app.getString(
                        R.string.svc_remote_start_failed,
                        t.message ?: t::class.java.simpleName,
                    )
                )
                stopInternal(keepStatus = true)
            }
        }
    }

    fun stop() = stopInternal(keepStatus = false)

    /** Revokes every open session (browsers will have to pair again). */
    fun disconnectAll() {
        sessions.clear()
        rotatePin()
        publishSessions()
    }

    @Synchronized
    private fun stopInternal(keepStatus: Boolean, reason: String? = null) {
        runCatching { serverSocket?.close() }
        serverSocket = null
        sessions.clear()
        scope?.cancel()
        scope = null
        if (!keepStatus) _status.value = Status(error = reason)
    }

    private fun bind(tls: RemoteTls.Material): SSLServerSocket {
        val any = InetAddress.getByName("0.0.0.0")
        val ss = try {
            tls.socketFactory.createServerSocket(DEFAULT_PORT, BACKLOG, any)
        } catch (_: BindException) {
            // Port taken (another app, previous instance not released yet):
            // use an ephemeral port, the displayed URL follows.
            tls.socketFactory.createServerSocket(0, BACKLOG, any)
        } as SSLServerSocket
        ss.enabledProtocols = ss.supportedProtocols
            .filter { it == "TLSv1.3" || it == "TLSv1.2" }
            .toTypedArray()
        return ss
    }

    private suspend fun acceptLoop(scope: CoroutineScope, ss: SSLServerSocket) {
        while (scope.isActive) {
            val sock = try {
                ss.accept()
            } catch (_: SocketException) {
                break // close() from stop()
            }
            if (!connections.tryAcquire()) {
                runCatching { sock.close() }
                continue
            }
            scope.launch {
                try {
                    handle(sock)
                } finally {
                    connections.release()
                }
            }
        }
    }

    private suspend fun handle(sock: Socket) {
        sock.soTimeout = SOCKET_TIMEOUT_MS
        val peer = sock.inetAddress?.hostAddress ?: "?"
        try {
            sock.use {
                val input = BufferedInputStream(it.getInputStream())
                val output = BufferedOutputStream(it.getOutputStream())
                val resp = try {
                    val req = MiniHttp.readRequest(input)
                    lastRequestMs = System.currentTimeMillis()
                    route(req, peer)
                } catch (e: HttpException) {
                    HttpResponse.error(e.status, e.message ?: "error")
                }
                MiniHttp.writeResponse(output, resp)
            }
        } catch (_: SSLException) {
            // Normal on first contact: the browser rejects the self-signed
            // cert until the user has accepted it.
        } catch (_: IOException) {
            // Timeout or connection dropped by the client.
        } catch (t: Throwable) {
            Log.w(TAG, "request from $peer failed", t)
        }
    }

    private suspend fun route(req: HttpRequest, peer: String): HttpResponse {
        if (!req.path.startsWith("/api/")) return asset(req)
        if (req.path == "/api/pair" && req.method == "POST") return pair(req)

        val token = req.header("authorization")?.removePrefix("Bearer ")?.trim()
        if (token.isNullOrEmpty() || !touchSession(token)) {
            return HttpResponse.error(401, "session expired: enter the PIN shown on the device")
        }
        if (req.path == "/api/logout" && req.method == "POST") {
            sessions.remove(token)
            publishSessions()
            return HttpResponse.ok()
        }
        return api.handle(req, peer)
    }

    private fun pair(req: HttpRequest): HttpResponse {
        val now = System.currentTimeMillis()
        if (now < lockedUntilMs) {
            val s = (lockedUntilMs - now + 999) / 1000
            return HttpResponse.error(429, "too many attempts: a new PIN is shown, try again in $s s")
        }
        val given = req.json().optString("pin").trim()
        val ok = synchronized(this) {
            val match = constantTimeEquals(given, pin)
            if (match) {
                failedAttempts = 0
            } else if (++failedAttempts >= MAX_PIN_ATTEMPTS) {
                failedAttempts = 0
                lockedUntilMs = now + LOCKOUT_MS
                rotatePin()
            }
            match
        }
        if (!ok) return HttpResponse.error(401, "incorrect PIN")
        val token = randomToken()
        sessions[token] = now
        rotatePin() // single use: another device will have to read the new PIN
        publishSessions()
        _status.update { it.copy(lastActivity = app.getString(R.string.svc_remote_browser_paired)) }
        return HttpResponse.ok(JSONObject().put("token", token))
    }

    private fun touchSession(token: String): Boolean {
        val now = System.currentTimeMillis()
        val last = sessions[token] ?: return false
        if (now - last > SESSION_TTL_MS) {
            sessions.remove(token)
            publishSessions()
            return false
        }
        sessions[token] = now
        return true
    }

    private fun asset(req: HttpRequest): HttpResponse {
        if (req.method != "GET" && req.method != "HEAD") return HttpResponse.error(405, "method not allowed")
        val (file, type) = when (req.path) {
            "/", "/index.html" -> "index.html" to "text/html; charset=utf-8"
            "/app.js" -> "app.js" to "text/javascript; charset=utf-8"
            "/app.css" -> "app.css" to "text/css; charset=utf-8"
            else -> return HttpResponse.error(404, "not found")
        }
        val bytes = app.assets.open("remote/$file").use { it.readBytes() }
        return HttpResponse(200, type, bytes)
    }

    private suspend fun idleWatchdog() {
        while (true) {
            delay(30_000)
            if (System.currentTimeMillis() - lastRequestMs > IDLE_TIMEOUT_MS) {
                stopInternal(
                    keepStatus = false,
                    reason = app.getString(R.string.svc_remote_idle_stopped, IDLE_TIMEOUT_MS / 60_000),
                )
                return
            }
        }
    }

    private fun rotatePin() {
        pin = (0 until PIN_LENGTH).joinToString("") { rng.nextInt(10).toString() }
        _status.update { if (it.running) it.copy(pin = pin) else it }
    }

    private fun publishSessions() = _status.update { it.copy(sessions = sessions.size, pin = pin) }

    private fun randomToken(): String {
        val b = ByteArray(32).also(rng::nextBytes)
        return Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun constantTimeEquals(a: String, b: String): Boolean =
        b.isNotEmpty() && MessageDigest.isEqual(a.toByteArray(), b.toByteArray())

    /**
     * IPv4 addresses reachable from the local network: those of the active
     * network if it is Wi-Fi or Ethernet, then the other LAN interfaces.
     * Mobile data (rmnet..., unreachable from the LAN), 464XLAT (`v4-rmnet*`,
     * 192.0.0.0/24) and our own VPN tun (192.0.2.0/24) are excluded.
     */
    private fun localUrls(port: Int): List<String> {
        val cm = app.getSystemService(ConnectivityManager::class.java)
        val active = cm?.activeNetwork
            ?.takeIf { network ->
                cm.getNetworkCapabilities(network)?.let {
                    it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                        it.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                } == true
            }
            ?.let { cm.getLinkProperties(it) }
            ?.linkAddresses.orEmpty().map { it.address }
        val others = runCatching {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { it.isUp && !it.isLoopback && NON_LAN_INTERFACES.none { prefix -> it.name.startsWith(prefix) } }
                .flatMap { it.inetAddresses.toList() }
        }.getOrDefault(emptyList())
        return (active + others)
            .filterIsInstance<Inet4Address>()
            .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress }
            .mapNotNull { it.hostAddress }
            .filter { !it.startsWith("192.0.2.") && !it.startsWith("192.0.0.") }
            .distinct()
            .map { "https://$it:$port/" }
    }

    private companion object {
        const val TAG = "mtls_bridge.remote"
        /** Interface prefixes never reachable from the LAN. */
        val NON_LAN_INTERFACES = listOf("tun", "rmnet", "v4-", "ccmni", "ppp", "ipsec", "dummy")
        const val DEFAULT_PORT = 47443
        const val BACKLOG = 8
        const val MAX_CONNECTIONS = 8
        const val SOCKET_TIMEOUT_MS = 20_000
        const val PIN_LENGTH = 6
        const val MAX_PIN_ATTEMPTS = 5
        const val LOCKOUT_MS = 30_000L
        const val SESSION_TTL_MS = 30L * 60 * 1000
        const val IDLE_TIMEOUT_MS = 15L * 60 * 1000
    }
}
