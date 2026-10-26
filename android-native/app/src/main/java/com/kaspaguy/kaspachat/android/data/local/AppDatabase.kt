package com.kaspaguy.kaspachat.android.data.local

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Upsert
import com.kaspaguy.kaspachat.android.security.LockedException
import kotlinx.coroutines.flow.Flow
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

/** A name this identity holds. `n` is the re-roll of a free name; `expiry` > 1 marks a Plus name (registry DAA). */
@Entity(tableName = "names")
data class NameEntity(@PrimaryKey val name: String, val n: Int?, val expiry: Long)

/**
 * A relay credit account. Only its derivation is stored (claim index, and whether it is that claim's SC-0024
 * extras account): the secret itself is re-derived from the seed when needed.
 */
@Entity(tableName = "accounts", primaryKeys = ["claimIndex", "extra"])
data class AccountEntity(val claimIndex: Int, val extra: Boolean, val kind: String, val credits: Int = 0)

@Entity(tableName = "orders")
data class OrderEntity(
    @PrimaryKey val id: String,
    val claimIndex: Int,
    val kind: String, // plus | claim | renew | topup
    val name: String?,
    val months: Int,
    val amountSompi: Long,
    val address: String,
    val status: String, // pending | paid | done | failed | expired | credited
    val created: Long,
    val extraSompi: Long = 0,
    val error: String? = null,
    val extraChecked: Long = 0,
)

@Entity(tableName = "kv")
data class KvEntity(@PrimaryKey val key: String, val value: String)

@Dao
interface StateDao {
    @Query("SELECT * FROM names ORDER BY expiry DESC, name")
    fun names(): Flow<List<NameEntity>>

    @Query("SELECT * FROM names")
    suspend fun namesNow(): List<NameEntity>

    @Upsert
    suspend fun upsertName(n: NameEntity)

    @Query("SELECT * FROM accounts")
    suspend fun accounts(): List<AccountEntity>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAccount(a: AccountEntity)

    @Query("UPDATE accounts SET credits = :credits WHERE claimIndex = :claimIndex AND extra = :extra")
    suspend fun setCredits(claimIndex: Int, extra: Boolean, credits: Int)

    @Query("SELECT COALESCE(SUM(credits), 0) FROM accounts")
    fun credits(): Flow<Int>

    @Query("SELECT * FROM orders ORDER BY created DESC")
    fun orders(): Flow<List<OrderEntity>>

    @Query("SELECT * FROM orders WHERE id = :id")
    fun order(id: String): Flow<OrderEntity?>

    @Query("SELECT * FROM orders")
    suspend fun ordersNow(): List<OrderEntity>

    @Upsert
    suspend fun upsertOrder(o: OrderEntity)

    @Query("SELECT value FROM kv WHERE key = :key")
    suspend fun get(key: String): String?

    @Query("SELECT value FROM kv WHERE key = :key")
    fun watch(key: String): Flow<String?>

    @Upsert
    suspend fun put(kv: KvEntity)
}

@Database(entities = [NameEntity::class, AccountEntity::class, OrderEntity::class, KvEntity::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun state(): StateDao
}

/** The SQLCipher database exists only while the session is unlocked; its key comes from the seed. */
class DatabaseHolder(private val context: Context) {
    @Volatile private var db: AppDatabase? = null

    init {
        System.loadLibrary("sqlcipher")
    }

    /** Takes ownership of [key] (SQLCipher wipes it after opening). */
    fun open(key: ByteArray) {
        close()
        db = Room.databaseBuilder(context, AppDatabase::class.java, NAME)
            .openHelperFactory(SupportOpenHelperFactory(key))
            .build()
    }

    fun close() {
        db?.close()
        db = null
    }

    /** A new or restored identity starts from an empty database (the old one is unreadable under a new key). */
    fun delete() {
        close()
        context.deleteDatabase(NAME)
    }

    val state: StateDao get() = (db ?: throw LockedException()).state()

    private companion object {
        const val NAME = "kaspachat.db"
    }
}
