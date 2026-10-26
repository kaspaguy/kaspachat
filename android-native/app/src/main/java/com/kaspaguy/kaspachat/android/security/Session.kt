package com.kaspaguy.kaspachat.android.security

import com.kaspaguy.kaspachat.android.core.NativeCore
import com.kaspaguy.kaspachat.android.core.toHex
import com.kaspaguy.kaspachat.android.core.wipe
import com.kaspaguy.kaspachat.android.data.local.DatabaseHolder
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class LockedException : IllegalStateException("locked")

/**
 * The unlocked state: the BIP-39 seed in memory (never on disk) and the encrypted database opened with a key
 * derived from it. Locking wipes the seed and closes the database.
 */
class Session(private val db: DatabaseHolder) {
    sealed interface State {
        data object Locked : State
        data class Unlocked(val ownerHex: String) : State
    }

    private var seed: ByteArray? = null
    private var ownerPub: ByteArray? = null
    private val _state = MutableStateFlow<State>(State.Locked)
    val state: StateFlow<State> = _state

    /** Takes ownership of [phrase] (UTF-8) and wipes it. */
    @Synchronized
    fun open(phrase: ByteArray) {
        val s = try { NativeCore.seedFromMnemonic(phrase) } finally { phrase.wipe() }
        lock()
        seed = s
        val owner = NativeCore.ownerPub(s)
        ownerPub = owner
        db.open(NativeCore.localKey(s, "database"))
        _state.value = State.Unlocked(owner.toHex())
    }

    @Synchronized
    fun lock() {
        db.close()
        seed?.wipe()
        seed = null
        ownerPub = null
        _state.value = State.Locked
    }

    /** Runs [block] with the seed; the array must not escape the block. */
    @Synchronized
    fun <T> withSeed(block: (ByteArray) -> T): T = block(seed ?: throw LockedException())

    val ownerHex: String get() = (state.value as? State.Unlocked)?.ownerHex ?: throw LockedException()
    fun ownerPubCopy(): ByteArray = ownerPub?.copyOf() ?: throw LockedException()
}
