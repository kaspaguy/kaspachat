package com.kaspaguy.kaspachat.android.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import com.kaspaguy.kaspachat.android.core.NativeCore
import com.kaspaguy.kaspachat.android.core.wipe
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The 24-word phrase at rest, in two layers:
 *  - inner: AES-256-GCM under scrypt(passcode) (N = 2^15, r = 8, p = 1, as protocol/src/vault.ts), done in the Rust
 *    core, so the phrase can't be opened without the passcode;
 *  - outer: AES-256-GCM under a non-exportable Android Keystore key (StrongBox when the device has it), so the file
 *    is useless off this device and a passcode guess needs this device.
 * Nothing else secret is stored: every key is derived from the phrase at unlock. The file lives in no-backup storage.
 */
class SeedVault(context: Context) {
    private val file = File(context.noBackupFilesDir, "seed.vault")
    private val attemptsFile = File(context.noBackupFilesDir, "seed.attempts")
    private val random = SecureRandom()

    val exists: Boolean get() = file.exists()

    fun create(phrase: ByteArray, passcode: String) {
        require(passcode.length >= MIN_PASSCODE) { "passcode too short" }
        val salt = ByteArray(16).also(random::nextBytes)
        val iv = ByteArray(12).also(random::nextBytes)
        val pass = passcode.toByteArray(Charsets.UTF_8)
        val key = NativeCore.vaultKey(pass, salt)
        pass.wipe()
        val inner = try { NativeCore.vaultSeal(key, iv, phrase) } finally { key.wipe() }
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, newKeystoreKey())
            updateAAD(AAD)
        }
        val outer = cipher.doFinal(inner)
        val json = JSONObject()
            .put("v", 1)
            .put("salt", b64(salt))
            .put("iv", b64(iv))
            .put("kiv", b64(cipher.iv))
            .put("ct", b64(outer))
        val tmp = File(file.parentFile, "seed.vault.tmp")
        tmp.writeText(json.toString())
        check(tmp.renameTo(file)) { "could not save the vault" }
        attemptsFile.delete()
    }

    sealed interface Unlock {
        class Ok(val phrase: ByteArray) : Unlock
        data object WrongPasscode : Unlock
        data class Wait(val seconds: Long) : Unlock
        /** The Keystore key is gone (e.g. the device's lock screen was removed): only the phrase can restore. */
        data object KeyLost : Unlock
    }

    /** The phrase's UTF-8 bytes on success; the caller wipes them. */
    fun unlock(passcode: String): Unlock {
        val wait = secondsToWait()
        if (wait > 0) return Unlock.Wait(wait)
        val json = JSONObject(file.readText())
        val inner = try {
            val key = (keystore().getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey ?: return Unlock.KeyLost
            Cipher.getInstance(TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, unb64(json.getString("kiv"))))
                updateAAD(AAD)
                doFinal(unb64(json.getString("ct")))
            }
        } catch (_: java.security.GeneralSecurityException) {
            return Unlock.KeyLost
        }
        val pass = passcode.toByteArray(Charsets.UTF_8)
        val key = NativeCore.vaultKey(pass, unb64(json.getString("salt")))
        pass.wipe()
        val phrase = NativeCore.vaultOpen(key, unb64(json.getString("iv")), inner)
        key.wipe()
        inner.wipe()
        if (phrase == null) {
            recordFailure()
            return Unlock.WrongPasscode
        }
        attemptsFile.delete()
        return Unlock.Ok(phrase)
    }

    /** Forget this device's copy (sign out / start over). The phrase is the only way back. */
    fun destroy() {
        file.delete()
        attemptsFile.delete()
        runCatching { keystore().deleteEntry(ALIAS) }
    }

    // Five free tries, then 30 s doubling per failure, capped at an hour. Kept in a file so restarts don't reset it.
    private fun secondsToWait(): Long {
        if (!attemptsFile.exists()) return 0
        val (n, last) = attemptsFile.readText().split(',').let { it[0].toInt() to it[1].toLong() }
        if (n < FREE_TRIES) return 0
        val delay = minOf(3600L, 30L shl minOf(n - FREE_TRIES, 7))
        return maxOf(0L, last / 1000 + delay - System.currentTimeMillis() / 1000)
    }

    private fun recordFailure() {
        val n = if (attemptsFile.exists()) attemptsFile.readText().substringBefore(',').toInt() else 0
        attemptsFile.writeText("${n + 1},${System.currentTimeMillis()}")
    }

    private fun keystore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun newKeystoreKey(): SecretKey {
        runCatching { keystore().deleteEntry(ALIAS) }
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            gen.init(spec(true))
            gen.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            gen.init(spec(false))
            gen.generateKey()
        }
    }

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

    companion object {
        const val MIN_PASSCODE = 8
        private const val FREE_TRIES = 5
        private const val ALIAS = "kaspachat.seedvault.v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val AAD = "kaspachat/android/seedvault/v1".toByteArray()
    }
}
