package com.douxev.mtls_bridge.data

/**
 * URL to enter in the target app to go through the proxy, or `null` if it is
 * not known yet (loopback on an ephemeral port: the actual port is only
 * visible in the BIND_OK event).
 */
fun ConfigEntity.clientUrl(): String? = when (mode) {
    ProxyMode.VPN ->
        if (!syntheticIp.isNullOrBlank() && syntheticPort != null) "http://$syntheticIp:$syntheticPort"
        else null
    ProxyMode.LOOPBACK -> {
        val p = loopbackPort
        if (p == null || p <= 0) null
        // With a token, this exact URL must be pasted into the target app,
        // otherwise the proxy rejects the request (fail-closed).
        else if (!pathToken.isNullOrBlank()) "http://127.0.0.1:$p/$pathToken/"
        else "http://127.0.0.1:$p/"
    }
}
