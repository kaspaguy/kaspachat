package com.kaspaguy.kaspachat.android.ui.topup

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kaspaguy.kaspachat.android.BuildConfig
import com.kaspaguy.kaspachat.android.data.remote.ConfigDto
import com.kaspaguy.kaspachat.android.domain.PaymentRepository
import com.kaspaguy.kaspachat.android.payment.KaspaPayment
import com.kaspaguy.kaspachat.android.ui.common.ErrorText
import com.kaspaguy.kaspachat.android.ui.common.Screen
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

class TopUpViewModel(private val payments: PaymentRepository) : ViewModel() {
    var config by mutableStateOf<ConfigDto?>(null)
        private set
    var kas by mutableIntStateOf(KaspaPayment.PAYG_MIN_KAS)
    var plusName by mutableStateOf("")
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
        private set

    init {
        viewModelScope.launch {
            config = runCatching { payments.config(refresh = true) }.getOrElse { error = "Can't reach KaspaChat: ${it.message}"; null }
        }
    }

    /** Credits a top-up buys: 75% of it pays message fees (the covenant's fixed split), as the relay credits it. */
    fun creditsFor(sompi: Long): Long = config?.let { (sompi * 3 / 4) / it.msgFee } ?: 0

    fun orderTopup(onOrder: (String) -> Unit) = order(onOrder) { payments.orderTopup(kas).id }

    fun orderPlus(onOrder: (String) -> Unit) = order(onOrder) {
        val name = plusName.trim().lowercase()
        val check = payments.checkName(name)
        if (!check.available) throw IllegalStateException("@$name isn't available${check.reason?.let { " ($it)" } ?: ""}.")
        payments.orderPlus(name).id
    }

    private fun order(onOrder: (String) -> Unit, f: suspend () -> String) {
        busy = true
        error = null
        viewModelScope.launch {
            runCatching { f() }.onSuccess(onOrder).onFailure { error = it.message ?: "Something went wrong." }
            busy = false
        }
    }
}

@Composable
fun TopUpScreen(vm: TopUpViewModel, onOrder: (String) -> Unit) = Screen {
    Text("Top up / Upgrade", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(12.dp))
    if (BuildConfig.STORE_BUILD) {
        // Store builds sell nothing inside the app (Play billing policy); credits bought elsewhere appear here.
        Text("Plus and top-ups are bought at kaspachat.com with the same recovery phrase. Your credits show up here automatically.")
        return@Screen
    }
    val cfg = vm.config
    ErrorText(vm.error)
    if (cfg == null) {
        Text("Loading prices…")
        return@Screen
    }

    Card(Modifier.fillMaxWidth()) {
        Text("Premium (Plus)", Modifier.padding(start = 16.dp, top = 16.dp), style = MaterialTheme.typography.titleMedium)
        Text("${KaspaPayment.formatKas(cfg.plusPrice)} KAS / month", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.headlineSmall)
        Text(
            "A name you choose (like bob-123), about ${cfg.creditsPerMonth} messages a month, encrypted backup and sync.",
            Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
        )
        OutlinedTextField(
            vm.plusName, { vm.plusName = it },
            label = { Text("Your Plus name") },
            prefix = { Text("@") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
        )
        Button({ vm.orderPlus(onOrder) }, Modifier.padding(16.dp), enabled = !vm.busy && vm.plusName.isNotBlank()) {
            Text("Pay ${KaspaPayment.formatKas(cfg.plusPrice)} KAS")
        }
    }
    Spacer(Modifier.height(16.dp))
    Card(Modifier.fillMaxWidth()) {
        val sompi = KaspaPayment.paygSompi(vm.kas)
        Text("Pay-as-you-go", Modifier.padding(start = 16.dp, top = 16.dp), style = MaterialTheme.typography.titleMedium)
        Text("${vm.kas} KAS", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.headlineSmall)
        Text("About ${vm.creditsFor(sompi)} messages. Top-up credits never expire.", Modifier.padding(horizontal = 16.dp))
        Slider(
            value = vm.kas.toFloat(),
            onValueChange = { vm.kas = it.roundToInt() },
            valueRange = KaspaPayment.PAYG_MIN_KAS.toFloat()..KaspaPayment.PAYG_MAX_KAS.toFloat(),
            steps = KaspaPayment.PAYG_MAX_KAS - KaspaPayment.PAYG_MIN_KAS - 1,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        Button({ vm.orderTopup(onOrder) }, Modifier.padding(16.dp), enabled = !vm.busy) { Text("Pay ${vm.kas} KAS") }
    }
}
