package com.douxev.mtls_bridge.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

class ProxyModeConverters {
    @TypeConverter fun toMode(v: String): ProxyMode = ProxyMode.valueOf(v)
    @TypeConverter fun fromMode(m: ProxyMode): String = m.name
    @TypeConverter fun toSecurity(v: String): KeySecurityLevel = KeySecurityLevel.valueOf(v)
    @TypeConverter fun fromSecurity(s: KeySecurityLevel): String = s.name
}

@Database(
    entities = [ConfigEntity::class, AuditEventEntity::class],
    // v5 adds `pathToken` (secret token in the HTTP path for loopback
    // isolation), v6 `extraCanonicalHosts`. Every version bump MUST have its
    // Migration below: configs reference non-exportable Keystore keys, so a
    // wiped database makes them unrecoverable.
    version = 6,
    exportSchema = true,
)
@TypeConverters(ProxyModeConverters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun configDao(): ConfigDao
    abstract fun auditDao(): AuditDao

    companion object {
        @Volatile private var instance: AppDatabase? = null

        val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE configs ADD COLUMN pathToken TEXT")
            }
        }

        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE configs ADD COLUMN extraCanonicalHosts TEXT")
            }
        }

        /**
         * Returns (or creates) the SQLCipher DB. The passphrase is derived from
         * a non-exportable AES key stored in the Android Keystore; see
         * [com.douxev.mtls_bridge.keystore.DbPassphraseProvider].
         */
        fun get(context: Context, passphrase: ByteArray): AppDatabase {
            instance?.let { return it }
            return synchronized(this) {
                instance ?: build(context, passphrase).also { instance = it }
            }
        }

        private fun build(context: Context, passphrase: ByteArray): AppDatabase {
            // SQLCipher 4.6: load the native library before creating the helper.
            System.loadLibrary("sqlcipher")
            val factory = SupportOpenHelperFactory(passphrase)
            return Room
                .databaseBuilder(context, AppDatabase::class.java, "mtls_bridge.db")
                .openHelperFactory(factory)
                .addMigrations(MIGRATION_4_5, MIGRATION_5_6)
                // Schemas v1-v3 predate the first commit (no record left to write
                // their migrations): only those remain destructive.
                .fallbackToDestructiveMigrationFrom(1, 2, 3)
                .build()
        }
    }
}
