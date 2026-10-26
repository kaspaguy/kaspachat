package com.kaspaguy.kaspachat.android.ui.topup

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.kaspaguy.kaspachat.android.BuildConfig
import com.kaspaguy.kaspachat.android.domain.PaymentRepository
import com.kaspaguy.kaspachat.android.payment.KaspaNetwork
import com.kaspaguy.kaspachat.android.payment.KaspaPayment
import com.kaspaguy.kaspachat.android.ui.common.ErrorText
import com.kaspaguy.kaspachat.android.ui.common.QrImage
import com.kaspaguy.kaspachat.android.ui.common.Screen
import com.kaspaguy.kaspachat.android.ui.home.statusLabel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class PaymentViewModel(private val orderId: String, private val payments: PaymentRepository) : ViewModel() {
    val order = payments.order(orderId).stateIn(viewModelScope, SharingStarted.Eagerly, null)
    var uri by mutableStateOf<String?>(null)
        private set
    var network by mutableStateOf<KaspaNetwork?>(null)
        private set
    var error by mutableStateOf<String?>(null)
        private set
    var faucetSent by mutableStateOf(false)
        private set

    init {
        viewModelScope.launch {
            runCatching {
                network = payments.network()
                order.collect { o -> if (o != null && uri == null) uri = payments.paymentUri(o) }
            }.onFailure { error = it.message }
        }
        // Payment monitoring: the relay watches the order's covenant address on chain; poll it until it settles.
        viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                val o = runCatching { payments.pollOrder(orderId) }.getOrNull()
                if (o != null && o.status != "pending" && o.status != "paid") break
                delay(POLL_MS)
            }
        }
    }

    fun testPay() = viewModelScope.launch {
        runCatching { payments.testPay(orderId) }.onSuccess { faucetSent = true }.onFailure { error = it.message }
    }

    private companion object {
        const val POLL_MS = 4_000L
    }
}

@Composable
fun PaymentScreen(vm: PaymentViewModel, onDone: () -> Unit) = Screen {
    val o by vm.order.collectAsStateWithLifecycle()
    val order = o ?: return@Screen
    val uri = vm.uri
    val context = LocalContext.current
    val clipboard = LocalClipboard.current
    val scope = rememberCoroutineScope()
    val kas = KaspaPayment.formatKas(order.amountSompi)
    fun copy(label: String, text: String) = scope.launch { clipboard.setClipEntry(ClipEntry(ClipData.newPlainText(label, text))) }

    Text(if (order.kind == "topup") "Top up $kas KAS" else "Plus for @${order.name}", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(4.dp))
    Text(statusLabel(order.status), color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.titleMedium)
    Spacer(Modifier.height(12.dp))

    when (order.status) {
        "pending" -> {
            Card(
                Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            ) {
                Text(
                    KaspaPayment.EXACT_AMOUNT_WARNING,
                    Modifier.padding(16.dp),
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(16.dp))
            if (uri != null) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                    QrImage(uri, 240.dp, "Payment QR code for $kas KAS")
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "Scan with a Kaspa wallet (Kaspium, KaspaCom): it fills in the address and the amount.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
            }
            Spacer(Modifier.height(16.dp))
            Text("Amount", style = MaterialTheme.typography.labelLarge)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("$kas KAS", Modifier.weight(1f), style = MaterialTheme.typography.titleLarge)
                TextButton({ copy("Amount", kas) }) { Text("Copy") }
            }
            Text("Address", style = MaterialTheme.typography.labelLarge)
            Text(order.address, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            TextButton({ copy("Kaspa address", order.address) }) { Text("Copy address") }
            if (uri != null) {
                OutlinedButton(
                    {
                        try {
                            context.startActivity(Intent(Intent.ACTION_VIEW, uri.toUri()))
                        } catch (_: ActivityNotFoundException) {
                            copy("Kaspa payment", uri)
                        }
                    },
                    Modifier.fillMaxWidth(),
                ) { Text("Open in wallet app") }
            }
            if (vm.network == KaspaNetwork.TESTNET && !BuildConfig.STORE_BUILD) {
                Spacer(Modifier.height(8.dp))
                OutlinedButton(vm::testPay, Modifier.fillMaxWidth(), enabled = !vm.faucetSent) {
                    Text(if (vm.faucetSent) "Test coins sent, waiting for the chain…" else "Testnet: pay with the test faucet")
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "This screen updates by itself once the payment is on chain. An order waits 2 hours for its payment.",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        "paid" -> Text("Payment received. Settling it on chain; this takes a few seconds.")
        "done" -> {
            Text(if (order.kind == "topup") "Your credits are ready." else "@${order.name} is yours. This month's credits are ready.")
            Spacer(Modifier.height(12.dp))
            Button(onDone, Modifier.fillMaxWidth()) { Text("Done") }
        }
        "credited", "expired" -> {
            Text(
                if (order.extraSompi > 0) "The full amount didn't arrive in time. What did arrive (${KaspaPayment.formatKas(order.extraSompi)} KAS) became message credits."
                else "No payment arrived in time. Nothing was charged; start a new order to try again.",
            )
            Spacer(Modifier.height(12.dp))
            Button(onDone, Modifier.fillMaxWidth()) { Text("Back") }
        }
        else -> {
            ErrorText(order.error ?: "This order failed.")
            Button(onDone, Modifier.fillMaxWidth()) { Text("Back") }
        }
    }
    ErrorText(vm.error)
}
