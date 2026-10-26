package com.kaspaguy.kaspachat.android.domain

import com.kaspaguy.kaspachat.android.core.NativeCore
import com.kaspaguy.kaspachat.android.core.hexToBytes
import com.kaspaguy.kaspachat.android.core.toHex
import com.kaspaguy.kaspachat.android.core.wipe
import com.kaspaguy.kaspachat.android.data.local.AccountEntity
import com.kaspaguy.kaspachat.android.data.local.DatabaseHolder
import com.kaspaguy.kaspachat.android.data.local.KvEntity
import com.kaspaguy.kaspachat.android.data.local.NameEntity
import com.kaspaguy.kaspachat.android.data.remote.AccountRequest
import com.kaspaguy.kaspachat.android.data.remote.ApiError
import com.kaspaguy.kaspachat.android.data.remote.DefaultNameRequest
import com.kaspaguy.kaspachat.android.data.remote.IndexerApi
import com.kaspaguy.kaspachat.android.data.remote.PayloadRequest
import com.kaspaguy.kaspachat.android.data.remote.PowSolution
import com.kaspaguy.kaspachat.android.data.remote.RelayApi
import com.kaspaguy.kaspachat.android.data.remote.api
import com.kaspaguy.kaspachat.android.security.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import kotlin.coroutines.coroutineContext

/** The tag bucket of a 16-byte tag: its first 12 bits (protocol/src/tags.ts `tagBucket`). */
fun tagBucket(tag: ByteArray): Int = ((tag[0].toInt() and 0xff) shl 4) or ((tag[1].toInt() and 0xff) shr 4)

/**
 * Identity on the network: the free @kv… name, the key bundle, the relay credit accounts. Mirrors the web app's
 * engine (app/src/lib/engine.ts) so the same phrase finds the same names and credits on every platform.
 */
class AccountRepository(
    private val relay: RelayApi,
    private val indexer: IndexerApi,
    private val session: Session,
    private val db: DatabaseHolder,
) {
    private val random = SecureRandom()
    private val claimLock = Mutex()

    /** Account secret number [i], hex, re-derived from the seed each time it is needed. */
    fun claimHex(i: Int): String = session.withSeed { seed -> NativeCore.claimSecret(seed, i).let { c -> c.toHex().also { c.wipe() } } }

    fun accountSecretHex(a: AccountEntity): String {
        val claim = session.withSeed { NativeCore.claimSecret(it, a.claimIndex) }
        if (!a.extra) return claim.toHex().also { claim.wipe() }
        val extra = NativeCore.extraSecret(claim)
        claim.wipe()
        return extra.toHex().also { extra.wipe() }
    }

    private suspend fun nextClaimIndex(): Int = claimLock.withLock {
        val i = db.state.get(KEY_ACCT_INDEX)?.toInt() ?: 0
        db.state.put(KvEntity(KEY_ACCT_INDEX, (i + 1).toString()))
        i
    }

    /**
     * Runs [f] with a fresh account secret. The relay refuses (409) a secret already in use, e.g. by an order still
     * open from before a restore: then the next one is taken.
     */
    suspend fun <T> withClaim(f: suspend (index: Int, claimHex: String) -> T): T {
        var tries = 0
        while (true) {
            val i = nextClaimIndex()
            try {
                return f(i, claimHex(i))
            } catch (e: ApiError) {
                if (!(e.status == 409 && "account secret" in (e.message ?: "")) || ++tries > ACCOUNT_SCAN_GAP) throw e
            }
        }
    }

    /** Free name re-roll [n] (0–2): the doorman's proof of work on this device, then the registration on chain. */
    suspend fun registerFree(n: Int = 0, onProgress: (String) -> Unit = {}): String {
        val owner = session.ownerHex
        val r = withClaim { index, claim ->
            onProgress("Getting a puzzle from the doorman…")
            val ch = api { relay.pow() }
            onProgress("Solving the anti-spam puzzle on this device…")
            val nonce = solvePow(ch.challenge, ch.bits)
            onProgress("Registering your name on the Kaspa network…")
            api { relay.registerDefault(DefaultNameRequest(owner, n, PowSolution(ch.challenge, nonce), claim)) }.also {
                db.state.insertAccount(AccountEntity(index, extra = false, kind = "welcome", credits = it.credits))
            }
        }
        db.state.upsertName(NameEntity(r.name, n, 0))
        if (db.state.get(KEY_NAME) == null) db.state.put(KvEntity(KEY_NAME, r.name))
        onProgress("Publishing your public keys…")
        publishBundle()
        return r.name
    }

    private suspend fun solvePow(challengeHex: String, bits: Int): String = withContext(Dispatchers.Default) {
        val c = challengeHex.hexToBytes()
        var start = 0L
        while (true) {
            coroutineContext.ensureActive()
            NativeCore.solvePow(c, bits, start, POW_SLICE)?.let { return@withContext it }
            start += POW_SLICE
        }
        @Suppress("UNREACHABLE_CODE") ""
    }

    suspend fun publishBundle() {
        val spkId = db.state.get(KEY_SPK_ID)?.toInt() ?: 1
        val aux = ByteArray(32).also(random::nextBytes)
        val payload = session.withSeed { NativeCore.bundlePublication(it, spkId, System.currentTimeMillis() / 1000, aux) }
        api { relay.publishBundle(PayloadRequest(payload.toHex())) }
        db.state.put(KvEntity(KEY_BUNDLE_AT, System.currentTimeMillis().toString()))
    }

    /** After a restore: names this key already holds (its derivable free names, and any Plus names). */
    suspend fun findMyNames(): List<NameEntity> {
        val owner = session.ownerPubCopy()
        val ownerHex = owner.toHex()
        val found = mutableListOf<NameEntity>()
        for (n in 0..2) {
            val name = NativeCore.defaultName(owner, n)
            val e = api { indexer.registryBucket(NativeCore.registryBucket(name)) }.entries.find { it.name == name && it.owner == ownerHex }
            if (e != null) found += NameEntity(name, n, e.expiry)
        }
        runCatching { api { indexer.registryOwner(ownerHex) } }.getOrNull()?.entries?.forEach { e ->
            if (e.name != null && found.none { it.name == e.name }) found += NameEntity(e.name, null, e.expiry)
        }
        return found
    }

    /** Adopts restored names, continues after the latest published prekey (WIRE_FORMAT §2), finds credit accounts. */
    suspend fun adoptNames(found: List<NameEntity>) {
        found.forEach { db.state.upsertName(it) }
        val current = found.firstOrNull { it.expiry > 1 } ?: found.firstOrNull()
        current?.let { db.state.put(KvEntity(KEY_NAME, it.name)) }
        val latest = runCatching { latestOwnSpkId() }.getOrNull()
        if (latest != null && latest >= 1) db.state.put(KvEntity(KEY_SPK_ID, (latest + 1).toString()))
        recoverAccounts()
        publishBundle()
    }

    private suspend fun latestOwnSpkId(): Long? {
        val owner = session.ownerPubCopy()
        val tag = NativeCore.bundleTag(owner)
        val hit = api { indexer.bundles(tagBucket(tag)) }.bundles.find { it.tag == tag.toHex() } ?: return null
        return NativeCore.ownBundleSpkId(hit.p.hexToBytes(), owner, System.currentTimeMillis() / 1000).takeIf { it >= 0 }
    }

    // Same scan as the web app: stop after ACCOUNT_SCAN_GAP unused secrets in a row.
    private suspend fun recoverAccounts() {
        var misses = 0
        var i = 0
        while (misses < ACCOUNT_SCAN_GAP && i < 200) {
            var used = false
            for (extra in listOf(false, true)) {
                val a = AccountEntity(i, extra, kind = "")
                val dto = runCatching { api { relay.account(AccountRequest(accountSecretHex(a))) } }.getOrNull() ?: continue
                db.state.insertAccount(a.copy(kind = dto.kind, credits = dto.credits))
                used = true
            }
            if (used) {
                db.state.put(KvEntity(KEY_ACCT_INDEX, (i + 1).toString()))
                misses = 0
            } else misses++
            i++
        }
    }

    /** Reads a held name's registry entry (its expiry marks it Plus). */
    suspend fun refreshName(name: String) {
        val e = api { indexer.registryBucket(NativeCore.registryBucket(name)) }.entries.find { it.name == name } ?: return
        val n = db.state.namesNow().find { it.name == name }?.n
        db.state.upsertName(NameEntity(name, n, e.expiry))
    }

    /** Credits held on the relay across all accounts (blind-token issuance comes with messaging). */
    suspend fun refreshCredits() {
        for (a in db.state.accounts()) {
            val dto = runCatching { api { relay.account(AccountRequest(accountSecretHex(a))) } }.getOrNull() ?: continue
            db.state.setCredits(a.claimIndex, a.extra, dto.credits)
        }
    }

    companion object {
        const val ACCOUNT_SCAN_GAP = 20
        private const val POW_SLICE = 1L shl 18
        const val KEY_ACCT_INDEX = "acctIndex"
        const val KEY_SPK_ID = "spkId"
        const val KEY_BUNDLE_AT = "bundleAt"
        const val KEY_NAME = "name"
    }
}
