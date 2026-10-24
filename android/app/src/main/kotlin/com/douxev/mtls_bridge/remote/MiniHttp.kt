package com.douxev.mtls_bridge.remote

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.URLDecoder
import org.json.JSONArray
import org.json.JSONObject

/**
 * HTTP/1.1 minimal pour la console d'administration LAN : une requête par
 * connexion (`Connection: close`), bodies à Content-Length uniquement,
 * limites strictes. Volontairement sans dépendance : la surface exposée au
 * réseau local reste petite et lisible.
 */
internal class HttpRequest(
    val method: String,
    /** Chemin sans query string, tel que reçu (pas de décodage). */
    val path: String,
    val query: Map<String, String>,
    /** Noms en minuscules. */
    val headers: Map<String, String>,
    val body: ByteArray,
) {
    fun header(name: String): String? = headers[name.lowercase()]

    fun json(): JSONObject {
        val text = String(body, Charsets.UTF_8)
        if (text.isBlank()) return JSONObject()
        return try {
            JSONObject(text)
        } catch (e: Exception) {
            throw HttpException(400, "JSON invalide")
        }
    }
}

internal class HttpResponse(
    val status: Int,
    val contentType: String,
    val body: ByteArray,
    val extraHeaders: Map<String, String> = emptyMap(),
) {
    companion object {
        fun json(status: Int, value: Any): HttpResponse {
            val text = when (value) {
                is JSONObject, is JSONArray -> value.toString()
                else -> JSONObject.wrap(value)?.toString() ?: "null"
            }
            return HttpResponse(status, "application/json; charset=utf-8", text.toByteArray())
        }

        fun ok(value: Any = JSONObject().put("ok", true)) = json(200, value)

        fun error(status: Int, message: String) =
            json(status, JSONObject().put("error", message))
    }
}

internal class HttpException(val status: Int, message: String) : Exception(message)

internal object MiniHttp {
    const val MAX_HEADER_BYTES = 16 * 1024
    /** Un bundle ou un .p12 encodés en base64 dans du JSON : quelques Mo max. */
    const val MAX_BODY_BYTES = 8 * 1024 * 1024

    fun readRequest(input: InputStream): HttpRequest {
        val head = readHead(input)
        val lines = head.split("\r\n")
        val requestLine = lines.first().split(' ')
        if (requestLine.size != 3 || !requestLine[2].startsWith("HTTP/1.")) {
            throw HttpException(400, "ligne de requête invalide")
        }
        val method = requestLine[0].uppercase()
        val target = requestLine[1]
        if (!target.startsWith("/")) throw HttpException(400, "cible invalide")

        val headers = HashMap<String, String>()
        for (line in lines.drop(1)) {
            if (line.isEmpty()) continue
            val idx = line.indexOf(':')
            if (idx <= 0) throw HttpException(400, "header invalide")
            headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
        }
        if (headers.containsKey("transfer-encoding")) {
            throw HttpException(501, "Transfer-Encoding non supporté")
        }
        val length = headers["content-length"]?.let {
            it.toIntOrNull() ?: throw HttpException(400, "Content-Length invalide")
        } ?: 0
        if (length < 0 || length > MAX_BODY_BYTES) throw HttpException(413, "requête trop volumineuse")
        val body = readExactly(input, length)

        val path = target.substringBefore('?')
        val query = target.substringAfter('?', "")
            .split('&')
            .filter { it.isNotEmpty() }
            .associate { kv ->
                val k = kv.substringBefore('=')
                val v = kv.substringAfter('=', "")
                decode(k) to decode(v)
            }
        return HttpRequest(method, path, query, headers, body)
    }

    fun writeResponse(out: OutputStream, resp: HttpResponse) {
        val sb = StringBuilder()
        sb.append("HTTP/1.1 ").append(resp.status).append(' ').append(reason(resp.status)).append("\r\n")
        val headers = linkedMapOf(
            "Content-Type" to resp.contentType,
            "Content-Length" to resp.body.size.toString(),
            "Connection" to "close",
            "Cache-Control" to "no-store",
            "X-Content-Type-Options" to "nosniff",
            "X-Frame-Options" to "DENY",
            "Referrer-Policy" to "no-referrer",
            // Tout est servi depuis l'appareil : aucun script, style ou image
            // externe, pas d'iframe.
            "Content-Security-Policy" to "default-src 'self'; img-src 'self' data:; " +
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        headers.putAll(resp.extraHeaders)
        for ((k, v) in headers) sb.append(k).append(": ").append(v).append("\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.ISO_8859_1))
        out.write(resp.body)
        out.flush()
    }

    private fun readHead(input: InputStream): String {
        val buf = ByteArrayOutputStream(1024)
        var matched = 0 // progression dans "\r\n\r\n"
        while (true) {
            val b = input.read()
            if (b < 0) throw HttpException(400, "connexion fermée avant la fin des headers")
            buf.write(b)
            if (buf.size() > MAX_HEADER_BYTES) throw HttpException(431, "headers trop gros")
            matched = when {
                b == '\r'.code && (matched == 0 || matched == 2) -> matched + 1
                b == '\n'.code && (matched == 1 || matched == 3) -> matched + 1
                b == '\r'.code -> 1
                else -> 0
            }
            if (matched == 4) break
        }
        val bytes = buf.toByteArray()
        return String(bytes, 0, bytes.size - 4, Charsets.ISO_8859_1)
    }

    private fun readExactly(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(out, off, n - off)
            if (r < 0) throw HttpException(400, "body incomplet")
            off += r
        }
        return out
    }

    private fun decode(s: String): String = try {
        URLDecoder.decode(s, "UTF-8")
    } catch (_: IllegalArgumentException) {
        s
    }

    private fun reason(status: Int) = when (status) {
        200 -> "OK"
        204 -> "No Content"
        400 -> "Bad Request"
        401 -> "Unauthorized"
        403 -> "Forbidden"
        404 -> "Not Found"
        405 -> "Method Not Allowed"
        409 -> "Conflict"
        413 -> "Payload Too Large"
        429 -> "Too Many Requests"
        431 -> "Request Header Fields Too Large"
        501 -> "Not Implemented"
        else -> "Internal Server Error"
    }
}
