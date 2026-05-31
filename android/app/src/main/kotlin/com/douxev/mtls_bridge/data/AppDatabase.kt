package com.douxev.mtls_bridge.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

class ProxyModeConverters {
    @TypeConverter fun toMode(v: String): ProxyMode = ProxyMode.valueOf(v)
    @TypeConverter fun fromMode(m: ProxyMode): String = m.name
    @TypeConverter fun toSecurity(v: String): KeySecurityLevel = KeySecurityLevel.valueOf(v)
    @TypeConverter fun fromSecurity(s: KeySecurityLevel): String = s.name
}

@Database(
    entities = [ConfigEntity::class, AuditEventEntity::class],
    // v4 ajoute le champ `needsKeystoreRefresh` (import depuis fichier
    // d'export). fallbackToDestructiveMigration ⇒ historique perdu en MVP.
    version = 4,
    exportSchema = false,
)
@TypeConverters(ProxyModeConverters::class)
abstract class AppDatabase : RoomDatabase() {
    abstract fun configDao(): ConfigDao
    abstract fun auditDao(): AuditDao

    companion object {
        @Volatile private var instance: AppDatabase? = null

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
                .fallbackToDestructiveMigration() // MVP — schéma stable visé v0.2
                .build()
        }
    }
}
