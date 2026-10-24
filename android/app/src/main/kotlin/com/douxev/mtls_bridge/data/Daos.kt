package com.douxev.mtls_bridge.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface ConfigDao {
    @Query("SELECT * FROM configs ORDER BY displayName ASC")
    fun observeAll(): Flow<List<ConfigEntity>>

    @Query("SELECT * FROM configs WHERE id = :id")
    suspend fun byId(id: String): ConfigEntity?

    @Query("SELECT * FROM configs")
    suspend fun all(): List<ConfigEntity>

    @Query("SELECT * FROM configs WHERE targetPackage = :pkg LIMIT 1")
    suspend fun findByTargetPackage(pkg: String): ConfigEntity?

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(config: ConfigEntity)

    @Update
    suspend fun update(config: ConfigEntity)

    @Query("DELETE FROM configs WHERE id = :id")
    suspend fun delete(id: String)

    @Query("UPDATE configs SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: String, enabled: Boolean)

    @Query("UPDATE configs SET enabled = 0 WHERE mode = :mode")
    suspend fun disableAllOfMode(mode: ProxyMode)
}

@Dao
interface AuditDao {
    @Query("SELECT * FROM audit_events WHERE configId = :configId ORDER BY timestampMs DESC LIMIT :limit")
    fun observeRecent(configId: String, limit: Int = 200): Flow<List<AuditEventEntity>>

    @Insert
    suspend fun insert(event: AuditEventEntity)

    /**
     * Purge proactive : on garde un horizon glissant pour éviter de gonfler la DB.
     * Appelé périodiquement par le service de premier plan.
     */
    @Query("DELETE FROM audit_events WHERE timestampMs < :olderThanMs")
    suspend fun purgeOlderThan(olderThanMs: Long)
}
