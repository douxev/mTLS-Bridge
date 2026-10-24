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
    // v5 ajoute `pathToken` (token secret dans le path HTTP pour isolation
    // loopback), v6 `extraCanonicalHosts`. Chaque montée de version DOIT avoir
    // sa Migration ci-dessous : les configs référencent des clés Keystore
    // non-exportables, une base effacée les rend irrécupérables.
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
         * Récupère (ou crée) la DB SQLCipher. La passphrase est dérivée d'une
         * clé AES non-exportable stockée dans le Keystore Android — voir
         * [com.douxev.mtls_bridge.keystore.DbPassphraseProvider].
         */
        fun get(context: Context, passphrase: ByteArray): AppDatabase {
            instance?.let { return it }
            return synchronized(this) {
                instance ?: build(context, passphrase).also { instance = it }
            }
        }

        private fun build(context: Context, passphrase: ByteArray): AppDatabase {
            // SQLCipher 4.6 : charger la lib native avant d'instancier le helper.
            System.loadLibrary("sqlcipher")
            val factory = SupportOpenHelperFactory(passphrase)
            return Room
                .databaseBuilder(context, AppDatabase::class.java, "mtls_bridge.db")
                .openHelperFactory(factory)
                .addMigrations(MIGRATION_4_5, MIGRATION_5_6)
                // Schémas v1-v3 antérieurs au premier commit (aucune trace pour
                // écrire leurs migrations) : seuls eux restent destructifs.
                .fallbackToDestructiveMigrationFrom(1, 2, 3)
                .build()
        }
    }
}
