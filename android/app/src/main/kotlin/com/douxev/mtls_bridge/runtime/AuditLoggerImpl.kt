package com.douxev.mtls_bridge.runtime

import com.douxev.mtls_bridge.data.AuditDao
import com.douxev.mtls_bridge.data.AuditEventEntity
import com.douxev.mtls_bridge.ffi.AuditLogger
import com.douxev.mtls_bridge.ffi.ProxyEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.consumeAsFlow
import kotlinx.coroutines.launch

/**
 * Pont entre les événements émis par le core Rust (sync, via callback uniffi)
 * et l'écriture en DB (suspend).
 *
 * Dispatch :
 * - Événements porteurs d'un `config_id` (BindOk, Accepted, BridgeFailed,
 *   VpnRouteHit…) → écrits sous ce configId.
 * - Événements globaux (VpnStarted, VpnRouteMissing, Stopped) → broadcast
 *   vers tous les `allConfigIds` connus, pour qu'ils apparaissent dans les
 *   logs de chaque config concernée par la session VPN.
 *
 * On enqueue dans un Channel pour ne pas bloquer le thread Rust/tokio sur
 * une écriture Room potentiellement lente.
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

    /** Renvoie (type, details, configId-cible-ou-null-pour-broadcast). */
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
}
