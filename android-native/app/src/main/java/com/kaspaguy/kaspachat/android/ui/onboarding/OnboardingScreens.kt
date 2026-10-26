package com.kaspaguy.kaspachat.android.ui.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.kaspaguy.kaspachat.android.ui.common.ErrorText
import com.kaspaguy.kaspachat.android.ui.common.Screen
import com.kaspaguy.kaspachat.android.ui.common.SecureWindow

@Composable
fun WelcomeScreen(onCreate: () -> Unit, onRestore: () -> Unit) = Screen {
    Spacer(Modifier.height(48.dp))
    Text("KaspaChat", style = MaterialTheme.typography.displaySmall)
    Spacer(Modifier.height(8.dp))
    Text(
        "End-to-end encrypted messages on Kaspa. Nobody, including us, can read them or see who you talk to.",
        style = MaterialTheme.typography.bodyLarge,
    )
    Spacer(Modifier.height(40.dp))
    Button(onCreate, Modifier.fillMaxWidth()) { Text("Create a new account") }
    Spacer(Modifier.height(12.dp))
    OutlinedButton(onRestore, Modifier.fillMaxWidth()) { Text("Restore with a recovery phrase") }
}

@Composable
fun ShowPhraseScreen(vm: OnboardingViewModel, onNext: () -> Unit) = Screen {
    SecureWindow()
    LaunchedEffect(Unit) { if (vm.words.isEmpty()) vm.newPhrase() }
    Text("Your recovery phrase", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(8.dp))
    Text(
        "Write these 24 words down on paper, in order, and keep them offline. They are the only way back into your " +
            "account: there is no reset, and nobody can recover them for you. Never type them into a website.",
    )
    Spacer(Modifier.height(16.dp))
    Card(Modifier.fillMaxWidth()) {
        vm.words.chunked(2).forEachIndexed { row, pair ->
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)) {
                pair.forEachIndexed { col, w ->
                    Text("${row * 2 + col + 1}. $w", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
    Spacer(Modifier.height(16.dp))
    var saved by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(saved, { saved = it })
        Text("I have written down all 24 words")
    }
    Spacer(Modifier.height(8.dp))
    Button(onNext, Modifier.fillMaxWidth(), enabled = saved) { Text("Continue") }
}

@Composable
fun ConfirmPhraseScreen(vm: OnboardingViewModel, onBack: () -> Unit, onConfirmed: () -> Unit) = Screen {
    SecureWindow()
    val answers = remember { mutableStateListOf("", "", "") }
    var wrong by remember { mutableStateOf(false) }
    Text("Check your copy", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(8.dp))
    Text("Type these words from your written phrase.")
    Spacer(Modifier.height(16.dp))
    vm.confirmPositions.forEachIndexed { k, pos ->
        OutlinedTextField(
            answers[k], { answers[k] = it; wrong = false },
            label = { Text("Word ${pos + 1}") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        )
    }
    if (wrong) ErrorText("That doesn't match. Check your written copy.")
    Spacer(Modifier.height(12.dp))
    Button({ if (vm.checkConfirmation(answers)) { vm.phraseConfirmed(); onConfirmed() } else wrong = true }, Modifier.fillMaxWidth()) {
        Text("Confirm")
    }
    TextButton(onBack) { Text("Show the phrase again") }
}

@Composable
fun RestoreScreen(vm: OnboardingViewModel, onNext: () -> Unit) = Screen {
    SecureWindow()
    var text by remember { mutableStateOf("") }
    Text("Restore your account", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(8.dp))
    Text("Enter your 24-word recovery phrase, separated by spaces.")
    Spacer(Modifier.height(16.dp))
    OutlinedTextField(
        text, { text = it; vm.error = null },
        label = { Text("Recovery phrase") },
        minLines = 4,
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
    )
    ErrorText(vm.error)
    Spacer(Modifier.height(12.dp))
    Button({ if (vm.setRestorePhrase(text)) { text = ""; onNext() } }, Modifier.fillMaxWidth()) { Text("Continue") }
}

@Composable
fun PasscodeScreen(vm: OnboardingViewModel, onDone: () -> Unit) = Screen {
    var pass by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    var problem by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(vm.name) { if (vm.name != null) onDone() }

    if (!vm.vaultCreated) {
        Text("Set a device passcode", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text(
            "Your recovery phrase is stored on this phone encrypted with this passcode and the phone's secure " +
                "hardware. You'll need it to open KaspaChat. At least 8 characters.",
        )
        Spacer(Modifier.height(16.dp))
        PasswordField(pass, { pass = it; problem = null }, "Passcode")
        PasswordField(repeat, { repeat = it; problem = null }, "Repeat passcode")
        ErrorText(problem ?: vm.error)
        Spacer(Modifier.height(12.dp))
        Button(
            {
                problem = vm.passcodeProblem(pass, repeat)
                if (problem == null) vm.finish(pass)
            },
            Modifier.fillMaxWidth(),
            enabled = !vm.busy,
        ) { Text("Save and continue") }
    } else {
        Text(if (vm.restoring) "Restoring your account" else "Getting your free name", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(8.dp))
        Text("Your free name looks like @kv7f3q9x. It comes with 10 free messages.")
        ErrorText(vm.error)
        if (!vm.busy && vm.error != null) Button(vm::register, Modifier.fillMaxWidth()) { Text("Try again") }
    }
    if (vm.busy) {
        Spacer(Modifier.height(24.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.width(24.dp).height(24.dp))
            Spacer(Modifier.width(12.dp))
            Text(vm.progress ?: "Working…")
        }
    }
}

@Composable
fun UnlockScreen(vm: UnlockViewModel, onUnlocked: () -> Unit, onRestore: () -> Unit) = Screen {
    var pass by remember { mutableStateOf("") }
    Spacer(Modifier.height(48.dp))
    Text("Unlock KaspaChat", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(16.dp))
    PasswordField(pass, { pass = it }, "Passcode")
    ErrorText(vm.error)
    Spacer(Modifier.height(12.dp))
    Button({ vm.unlock(pass) { pass = ""; onUnlocked() } }, Modifier.fillMaxWidth(), enabled = !vm.busy && pass.isNotEmpty()) {
        Text(if (vm.busy) "Unlocking…" else "Unlock")
    }
    Spacer(Modifier.height(24.dp))
    var confirmForget by remember(vm.keyLost) { mutableStateOf(vm.keyLost) }
    if (!confirmForget) {
        TextButton({ confirmForget = true }) { Text("Forgot the passcode? Restore with your recovery phrase") }
    } else {
        Text(
            "This removes the account from this phone. Without your 24-word recovery phrase it cannot be recovered.",
            color = MaterialTheme.colorScheme.error,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton({ confirmForget = false }) { Text("Cancel") }
            Button({ vm.forgetDevice(); onRestore() }) { Text("Remove and restore") }
        }
    }
}

@Composable
private fun PasswordField(value: String, onChange: (String) -> Unit, label: String) = OutlinedTextField(
    value, onChange,
    label = { Text(label) },
    singleLine = true,
    visualTransformation = PasswordVisualTransformation(),
    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
)
