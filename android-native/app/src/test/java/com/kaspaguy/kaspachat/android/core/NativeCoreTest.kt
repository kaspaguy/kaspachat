package com.kaspaguy.kaspachat.android.core

import com.kaspaguy.kaspachat.android.domain.tagBucket
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** The real JNI bridge, loaded from the host build of android-native/core, against protocol/vectors/v1.json. */
class NativeCoreTest {
    private val vectors = Json.parseToJsonElement(File("../../protocol/vectors/v1.json").readText()).jsonObject["vectors"]!!.jsonArray
    private fun vector(id: String) = vectors.first { it.jsonObject["id"]!!.jsonPrimitive.content == id }.jsonObject
    private fun JsonObject.str(vararg path: String): String =
        path.dropLast(1).fold(this) { o, k -> o[k]!!.jsonObject }[path.last()]!!.jsonPrimitive.content

    @Test fun keysFromPhraseMatchVectors() {
        for (id in listOf("keys-alice", "keys-bob")) {
            val v = vector(id)
            val seed = NativeCore.seedFromMnemonic(v.str("input", "mnemonic").toByteArray())
            assertEquals(v.str("expected", "seed"), seed.toHex())
            assertEquals(v.str("expected", "owner_pub"), NativeCore.ownerPub(seed).toHex())
        }
    }

    @Test fun defaultNamesMatchVectors() {
        val v = vector("registry-default-names")
        val owners = v["input"]!!.jsonObject["owner_pubs"]!!.jsonArray
        val names = v["expected"]!!.jsonObject["names"]!!.jsonArray
        owners.zip(names).forEach { (o, per) ->
            per.jsonArray.forEachIndexed { n, name -> assertEquals(name.jsonPrimitive.content, NativeCore.defaultName(o.jsonPrimitive.content.hexToBytes(), n)) }
        }
    }

    @Test fun registryBucketsMatchVectors() {
        val v = vector("buckets-registry")
        val names = v["input"]!!.jsonObject["names"]!!.jsonArray.map { it.jsonPrimitive.content }
        val buckets = v["expected"]!!.jsonObject["buckets"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }
        assertEquals(buckets, names.map(NativeCore::registryBucket))
    }

    @Test fun newPhraseIsValid24Words() {
        val m = NativeCore.mnemonicFromEntropy(ByteArray(32) { it.toByte() })
        assertEquals(24, m.split(' ').size)
        assertTrue(NativeCore.isValidMnemonic(m.toByteArray()))
        assertFalse(NativeCore.isValidMnemonic("abandon ".repeat(24).trim().toByteArray()))
        assertThrows(IllegalArgumentException::class.java) { NativeCore.seedFromMnemonic("not a phrase".toByteArray()) }
    }

    @Test fun bundlePublicationIsOwnAndCurrent() {
        val seed = NativeCore.seedFromMnemonic(vector("keys-bob").str("input", "mnemonic").toByteArray())
        val owner = NativeCore.ownerPub(seed)
        val now = 1_760_000_000L
        val p = NativeCore.bundlePublication(seed, 3, now, ByteArray(32))
        assertEquals(1536, p.size)
        assertArrayEquals(NativeCore.bundleTag(owner), p.copyOfRange(1, 17))
        assertEquals(3L, NativeCore.ownBundleSpkId(p, owner, now))
        assertEquals(-1L, NativeCore.ownBundleSpkId(p, ByteArray(32), now))
        assertTrue(tagBucket(NativeCore.bundleTag(owner)) in 0..4095)
    }

    @Test fun claimSecretsMatchTheWebApp() {
        val seed = ByteArray(64) { 1 }
        val claim = NativeCore.claimSecret(seed, 0)
        assertEquals(File("../core/testdata/claim0.hex").readText(), claim.toHex())
        assertEquals(File("../core/testdata/extra0.hex").readText(), NativeCore.extraSecret(claim).toHex())
    }

    @Test fun vaultLayerRejectsWrongPasscode() {
        val salt = ByteArray(16) { 3 }
        val iv = ByteArray(12) { 4 }
        val ct = NativeCore.vaultSeal(NativeCore.vaultKey("correct horse".toByteArray(), salt), iv, "phrase".toByteArray())
        assertEquals("phrase", String(NativeCore.vaultOpen(NativeCore.vaultKey("correct horse".toByteArray(), salt), iv, ct)!!))
        assertNull(NativeCore.vaultOpen(NativeCore.vaultKey("correct horsf".toByteArray(), salt), iv, ct))
    }

    @Test fun powSolvesSlices() {
        val c = ByteArray(32) { 5 }
        var start = 0L
        var nonce: String? = null
        while (nonce == null) {
            nonce = NativeCore.solvePow(c, 10, start, 1L shl 12)
            start += 1L shl 12
        }
        val h = java.security.MessageDigest.getInstance("SHA-256").digest(c + nonce.toByteArray())
        assertTrue(h[0].toInt() == 0 && (h[1].toInt() and 0xc0) == 0)
    }
}
