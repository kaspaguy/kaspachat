package com.kaspaguy.kaspachat.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kaspaguy.kaspachat.android.core.NativeCore
import com.kaspaguy.kaspachat.android.data.local.DatabaseHolder
import com.kaspaguy.kaspachat.android.data.local.KvEntity
import com.kaspaguy.kaspachat.android.security.LockedException
import com.kaspaguy.kaspachat.android.security.SeedVault
import com.kaspaguy.kaspachat.android.security.Session
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** On a real device or emulator: the Keystore-wrapped seed vault, the native library, and the SQLCipher database. */
@RunWith(AndroidJUnit4::class)
class DeviceSecurityTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val vault = SeedVault(context)
    private val phrase = NativeCore.mnemonicFromEntropy(ByteArray(32) { 9 })

    @After fun cleanUp() {
        vault.destroy()
        DatabaseHolder(context).delete()
    }

    @Test fun vaultOpensOnlyWithThePasscode() {
        vault.create(phrase.toByteArray(), "passcode-123")
        assertTrue(vault.exists)
        val raw = File(context.noBackupFilesDir, "seed.vault").readText()
        assertFalse("phrase must not be on disk in clear", phrase.split(' ').any { it.length > 4 && raw.contains(it) })

        val ok = vault.unlock("passcode-123")
        assertTrue(ok is SeedVault.Unlock.Ok)
        assertEquals(phrase, String((ok as SeedVault.Unlock.Ok).phrase))
        assertEquals(SeedVault.Unlock.WrongPasscode, vault.unlock("passcode-124"))
    }

    @Test fun repeatedWrongPasscodesAreThrottled() {
        vault.create(phrase.toByteArray(), "passcode-123")
        repeat(5) { assertEquals(SeedVault.Unlock.WrongPasscode, vault.unlock("nope-nope")) }
        assertTrue(vault.unlock("passcode-123") is SeedVault.Unlock.Wait)
    }

    @Test fun keyLossIsReportedNotCrashed() {
        vault.create(phrase.toByteArray(), "passcode-123")
        java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry("kaspachat.seedvault.v1")
        assertEquals(SeedVault.Unlock.KeyLost, vault.unlock("passcode-123"))
    }

    @Test fun sessionOpensEncryptedDatabaseAndLockWipes() = runBlocking {
        val db = DatabaseHolder(context)
        db.delete()
        val session = Session(db)
        session.open(phrase.toByteArray())
        db.state.put(KvEntity("probe", "1"))
        assertEquals("1", db.state.get("probe"))
        session.lock()
        try {
            db.state
            fail("database must be closed when locked")
        } catch (_: LockedException) {
        }
        val file = context.getDatabasePath("kaspachat.db")
        assertFalse("database file must not be plain SQLite", file.readBytes().copyOf(16).decodeToString().startsWith("SQLite format 3"))
    }
}
