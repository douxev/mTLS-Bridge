package com.douxev.mtls_bridge.data

/**
 * URL à saisir dans l'app cible pour passer par le proxy, ou `null` si elle
 * n'est pas encore connue (loopback sur port éphémère : le port réel n'est
 * visible que dans l'événement BIND_OK).
 */
fun ConfigEntity.clientUrl(): String? = when (mode) {
    ProxyMode.VPN ->
        if (!syntheticIp.isNullOrBlank() && syntheticPort != null) "http://$syntheticIp:$syntheticPort"
        else null
    ProxyMode.LOOPBACK -> {
        val p = loopbackPort
        if (p == null || p <= 0) null
        // Avec un token, c'est cette URL exacte qu'il faut coller dans l'app
        // cible, sinon le proxy refuse fail-closed.
        else if (!pathToken.isNullOrBlank()) "http://127.0.0.1:$p/$pathToken/"
        else "http://127.0.0.1:$p/"
    }
}
