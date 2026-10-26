package com.kaspaguy.kaspachat.android.ui.onboarding

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaspaguy.kaspachat.android.core.NativeCore
import com.kaspaguy.kaspachat.android.core.wipe
import com.kaspaguy.kaspachat.android.data.local.DatabaseHolder
import com.kaspaguy.kaspachat.android.domain.AccountRepository
import com.kaspaguy.kaspachat.android.security.SeedVault
import com.kaspaguy.kaspachat.android.security.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom

class OnboardingViewModel(
    private val vault: SeedVault,
    private val session: Session,
    private val db: DatabaseHolder,
    private val accounts: AccountRepository,
) : ViewModel() {
    private val random = SecureRandom()
    private var phrase: ByteArray? = null

    var restoring by mutableStateOf(false)
        private set
    var words by mutableStateOf<List<String>>(emptyList())
        private set
    var confirmPositions by mutableStateOf<List<Int>>(emptyList())
        private set
    var busy by mutableStateOf(false)
        private set
    var progress by mutableStateOf<String?>(null)
        private set
    var error by mutableStateOf<String?>(null)
    var vaultCreated by mutableStateOf(false)
        private set
    var name by mutableStateOf<String?>(null)
        private set

    fun newPhrase() {
        restoring = false
        val entropy = ByteArray(32).also(random::nextBytes)
        val m = NativeCore.mnemonicFromEntropy(entropy)
        entropy.wipe()
        replacePhrase(m.toByteArray(Charsets.UTF_8))
        words = m.split(' ')
        confirmPositions = (0 until 24).shuffled(random).take(3).sorted()
    }

    fun checkConfirmation(answers: List<String>): Boolean =
        confirmPositions.zip(answers).all { (i, a) -> words[i] == a.trim().lowercase() }

    /** The phrase is only shown during sign-up; once confirmed it lives in the vault alone. */
    fun phraseConfirmed() {
        words = emptyList()
    }

    fun setRestorePhrase(text: String): Boolean {
        val normalized = text.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        val bytes = normalized.joinToString(" ").toByteArray(Charsets.UTF_8)
        if (normalized.size != 24 || !NativeCore.isValidMnemonic(bytes)) {
            bytes.wipe()
            error = "That isn't a valid 24-word recovery phrase. Check the spelling and the order of the words."
            return false
        }
        error = null
        restoring = true
        replacePhrase(bytes)
        return true
    }

    private fun replacePhrase(b: ByteArray) {
        phrase?.wipe()
        phrase = b
    }

    fun passcodeProblem(pass: String, repeat: String): String? = when {
        pass.length < SeedVault.MIN_PASSCODE -> "Use at least ${SeedVault.MIN_PASSCODE} characters."
        pass != repeat -> "The two passcodes don't match."
        else -> null
    }

    /** Seals the phrase under the passcode and this device's Keystore, unlocks, then registers or restores. */
    fun finish(pass: String) {
        val p = phrase ?: return
        busy = true
        error = null
        viewModelScope.launch {
            try {
                withContext(Dispatchers.Default) {
                    progress = "Encrypting your recovery phrase on this device…"
                    db.delete()
                    vault.create(p, pass)
                    session.open(p.copyOf())
                }
                p.wipe()
                phrase = null
                vaultCreated = true
                register()
            } catch (e: Exception) {
                error = "Could not set up this device: ${e.message ?: "unknown error"}"
                busy = false
                progress = null
            }
        }
    }

    /** Also the retry after a network failure: the vault is already in place by then. */
    fun register() {
        busy = true
        error = null
        viewModelScope.launch {
            try {
                name = withContext(Dispatchers.IO) {
                    if (restoring) {
                        progress = "Looking for your names…"
                        val found = accounts.findMyNames()
                        if (found.isNotEmpty()) {
                            progress = "Restoring your names and credits…"
                            accounts.adoptNames(found)
                            return@withContext found.first().name
                        }
                    }
                    accounts.registerFree { progress = it }
                }
            } catch (e: Exception) {
                error = "Registration failed: ${e.message ?: "network error"}. Check your connection and try again."
            } finally {
                busy = false
                progress = null
            }
        }
    }

    override fun onCleared() {
        phrase?.wipe()
        phrase = null
    }
}

class UnlockViewModel(private val vault: SeedVault, private val session: Session) : ViewModel() {
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
        private set
    var keyLost by mutableStateOf(false)
        private set

    fun unlock(pass: String, onDone: () -> Unit) {
        busy = true
        error = null
        viewModelScope.launch {
            when (val r = withContext(Dispatchers.Default) { vault.unlock(pass) }) {
                is SeedVault.Unlock.Ok -> {
                    withContext(Dispatchers.Default) { session.open(r.phrase) }
                    onDone()
                }
                SeedVault.Unlock.WrongPasscode -> error = "Wrong passcode."
                is SeedVault.Unlock.Wait -> error = "Too many wrong tries. Wait ${r.seconds} seconds."
                SeedVault.Unlock.KeyLost -> {
                    keyLost = true
                    error = "This device's key store no longer holds the vault key (for example, the screen lock was removed). Restore with your recovery phrase."
                }
            }
            busy = false
        }
    }

    fun forgetDevice() {
        session.lock()
        vault.destroy()
    }
}
