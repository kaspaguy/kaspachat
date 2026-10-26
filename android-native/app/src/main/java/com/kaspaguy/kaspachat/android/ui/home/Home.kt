package com.kaspaguy.kaspachat.android.ui.home

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.kaspaguy.kaspachat.android.data.local.DatabaseHolder
import com.kaspaguy.kaspachat.android.data.local.OrderEntity
import com.kaspaguy.kaspachat.android.domain.AccountRepository
import com.kaspaguy.kaspachat.android.domain.PaymentRepository
import com.kaspaguy.kaspachat.android.payment.KaspaPayment
import com.kaspaguy.kaspachat.android.security.Session
import com.kaspaguy.kaspachat.android.ui.common.Screen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class HomeViewModel(
    db: DatabaseHolder,
    private val session: Session,
    private val accounts: AccountRepository,
    private val payments: PaymentRepository,
) : ViewModel() {
    val name = db.state.watch(AccountRepository.KEY_NAME).stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)
    val credits = db.state.credits().stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
    val orders = payments.orders().stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    fun refresh() = viewModelScope.launch(Dispatchers.IO) {
        runCatching { payments.pollOrders() }
        runCatching { accounts.refreshCredits() }
    }

    fun lock() = session.lock()
}

@Composable
fun HomeScreen(vm: HomeViewModel, onTopUp: () -> Unit, onOrder: (String) -> Unit, onLocked: () -> Unit) = Screen {
    val name by vm.name.collectAsStateWithLifecycle()
    val credits by vm.credits.collectAsStateWithLifecycle()
    val orders by vm.orders.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { vm.refresh() }

    Row(Modifier.fillMaxWidth()) {
        Text(name?.let { "@$it" } ?: "No name yet", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
        TextButton({ vm.lock(); onLocked() }) { Text("Lock") }
    }
    Spacer(Modifier.height(12.dp))
    Card(Modifier.fillMaxWidth()) {
        Text("Message credits", Modifier.padding(start = 16.dp, top = 16.dp), style = MaterialTheme.typography.labelLarge)
        Text("$credits", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.displaySmall)
        Button(onTopUp, Modifier.padding(16.dp)) { Text("Top up / Upgrade") }
    }
    Spacer(Modifier.height(20.dp))
    Text("Chats", style = MaterialTheme.typography.titleMedium)
    Text(
        "Messaging arrives in the next build of this app. Your name, keys and credits are already set up.",
        style = MaterialTheme.typography.bodyMedium,
    )
    if (orders.isNotEmpty()) {
        Spacer(Modifier.height(20.dp))
        Text("Payments", style = MaterialTheme.typography.titleMedium)
        orders.forEach { o -> OrderRow(o) { onOrder(o.id) }; HorizontalDivider() }
    }
}

@Composable
private fun OrderRow(o: OrderEntity, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp)) {
        val what = if (o.kind == "topup") "Top-up" else "Plus @${o.name}"
        Text("$what · ${KaspaPayment.formatKas(o.amountSompi)} KAS", Modifier.weight(1f))
        Text(statusLabel(o.status), color = MaterialTheme.colorScheme.secondary)
    }
}

fun statusLabel(status: String) = when (status) {
    "pending" -> "Waiting for payment"
    "paid" -> "Paid, confirming"
    "done" -> "Done"
    "credited" -> "Part payment credited"
    "expired" -> "Expired"
    "failed" -> "Failed"
    else -> status
}
