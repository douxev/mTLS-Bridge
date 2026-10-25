package com.douxev.mtls_bridge.runtime

import com.douxev.mtls_bridge.data.AuditDao
import com.douxev.mtls_bridge.data.AuditEventEntity
import com.douxev.mtls_bridge.ffi.AuditLogger
import com.douxev.mtls_bridge.ffi.ProxyEvent
import com.douxev.mtls_bridge.ffi.TokenRejection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.launch

/**
 * Bridge between the events emitted by the Rust core (sync, via a uniffi
 * callback) and the DB write (suspend).
 *
 * Dispatch:
 * - Events carrying a `config_id` (BindOk, Accepted, BridgeFailed,
 *   VpnRouteHit...) are written under that configId.
 * - Global events (VpnStarted, VpnRouteMissing, Stopped) are broadcast to
 *   every known `allConfigIds`, so they show up in the logs of each config
 *   involved in the VPN session.
 *
 * Events are queued in a Channel so the Rust/tokio thread is never blocked
 * on a potentially slow Room write.
 */
class AuditLoggerImpl(
    private val allConfigIds: List<String>,
    private val dao: AuditDao,
) : AuditLogger {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val queue = Channel<AuditEventEntity>(capacity = Channel.BUFFERED)

    init {
        scope.launch {
            queue.consumeAsFlow().collect { ev -> dao.insert(ev) }
        }
    }

    override fun record(event: ProxyEvent) {
        val (type, details, targetConfigId) = serialize(event)
        val timestamp = System.currentTimeMillis()
        val targets = if (targetConfigId != null) listOf(targetConfigId) else allConfigIds
        for (cid in targets) {
            queue.trySend(
                AuditEventEntity(
                    configId = cid,
                    timestampMs = timestamp,
                    eventType = type,
                    details = details,
                )
            )
        }
    }

    fun stop() {
        queue.close()
    }

    /** Returns (type, details, target configId or null for broadcast). */
    private fun serialize(event: ProxyEvent): Triple<String, String, String?> = when (event) {
        is ProxyEvent.BindOk ->
            Triple("BIND_OK", "port=${event.port}", event.configId)
        is ProxyEvent.BindFailed ->
            Triple("BIND_FAILED", event.reason, event.configId)
        is ProxyEvent.Accepted ->
            Triple("ACCEPTED", "uid=${event.peerUid}", event.configId)
        is ProxyEvent.RejectedUidMismatch ->
            Triple(
                "REJECTED_UID_MISMATCH",
                "peer=${event.peerUid} expected=${event.expectedUid}",
                event.configId,
            )
        is ProxyEvent.RejectedUidUnknown ->
            Triple("REJECTED_UID_UNKNOWN", "", event.configId)
        // Reason only: never the token, the cookie or the requested path.
        is ProxyEvent.RejectedToken ->
            Triple("REJECTED_TOKEN", tokenRejectionDetails(event.reason), event.configId)
        is ProxyEvent.VpnStarted ->
            Triple("VPN_STARTED", "routes=${event.routeCount}", null)
        is ProxyEvent.VpnRouteHit ->
            Triple(
                "VPN_ROUTE_HIT",
                "${event.syntheticIp}:${event.syntheticPort}",
                event.configId,
            )
        is ProxyEvent.VpnRouteMissing ->
            Triple(
                "VPN_ROUTE_MISSING",
                "${event.syntheticIp}:${event.syntheticPort}",
                null,
            )
        is ProxyEvent.BridgeFailed ->
            Triple("BRIDGE_FAILED", event.reason, event.configId)
        is ProxyEvent.Stopped ->
            Triple("STOPPED", "", null)
    }

    private fun tokenRejectionDetails(reason: TokenRejection): String = when (reason) {
        TokenRejection.INVALID_TOKEN -> "missing or invalid token or session cookie"
        TokenRejection.NOT_HTTP -> "non-HTTP stream"
        TokenRejection.HEADERS_TOO_LARGE -> "headers too large"
    }
}
