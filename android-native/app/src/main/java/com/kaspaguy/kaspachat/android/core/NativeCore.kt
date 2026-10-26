package com.kaspaguy.kaspachat.android.core

/**
 * The Rust core (android-native/core, wrapping rust-impl). All protocol crypto happens there; this app never
 * implements a primitive itself. Secrets go in and out as byte arrays the caller wipes when done.
 */
object NativeCore {
    init {
        System.loadLibrary("kaspachat_core")
    }

    @JvmStatic external fun mnemonicFromEntropy(entropy: ByteArray): String
    @JvmStatic external fun isValidMnemonic(phrase: ByteArray): Boolean
    @JvmStatic external fun seedFromMnemonic(phrase: ByteArray): ByteArray
    @JvmStatic external fun ownerPub(seed: ByteArray): ByteArray
    @JvmStatic external fun defaultName(ownerPub: ByteArray, n: Int): String
    @JvmStatic external fun registryBucket(name: String): Int
    @JvmStatic external fun bundlePublication(seed: ByteArray, spkId: Int, createdSec: Long, aux: ByteArray): ByteArray
    @JvmStatic external fun bundleTag(ownerPub: ByteArray): ByteArray

    /** The bundle's spkId, or -1 if [payload] is not a valid, current publication by [ownerPub]. */
    @JvmStatic external fun ownBundleSpkId(payload: ByteArray, ownerPub: ByteArray, nowSec: Long): Long
    @JvmStatic external fun claimSecret(seed: ByteArray, index: Int): ByteArray
    @JvmStatic external fun extraSecret(claim: ByteArray): ByteArray
    @JvmStatic external fun localKey(seed: ByteArray, label: String): ByteArray
    @JvmStatic external fun vaultKey(passcode: ByteArray, salt: ByteArray): ByteArray
    @JvmStatic external fun vaultSeal(key: ByteArray, iv: ByteArray, plain: ByteArray): ByteArray

    /** Null when the passcode is wrong or the blob was altered. */
    @JvmStatic external fun vaultOpen(key: ByteArray, iv: ByteArray, ct: ByteArray): ByteArray?

    /** A nonce among [start, start + count) meeting the doorman's target, or null. */
    @JvmStatic external fun solvePow(challenge: ByteArray, bits: Int, start: Long, count: Long): String?
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0 && all { it in '0'..'9' || it in 'a'..'f' }) { "not lowercase hex" }
    return ByteArray(length / 2) { ((Character.digit(this[2 * it], 16) shl 4) or Character.digit(this[2 * it + 1], 16)).toByte() }
}

fun ByteArray.wipe() = fill(0)
