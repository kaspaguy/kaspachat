package com.kaspaguy.kaspachat.android.domain

import com.kaspaguy.kaspachat.android.data.local.AccountEntity
import com.kaspaguy.kaspachat.android.data.local.DatabaseHolder
import com.kaspaguy.kaspachat.android.data.local.KvEntity
import com.kaspaguy.kaspachat.android.data.local.NameEntity
import com.kaspaguy.kaspachat.android.data.local.OrderEntity
import com.kaspaguy.kaspachat.android.data.remote.AccountRequest
import com.kaspaguy.kaspachat.android.data.remote.ConfigDto
import com.kaspaguy.kaspachat.android.data.remote.NameCheck
import com.kaspaguy.kaspachat.android.data.remote.OrderCreated
import com.kaspaguy.kaspachat.android.data.remote.PlusOrderRequest
import com.kaspaguy.kaspachat.android.data.remote.RelayApi
import com.kaspaguy.kaspachat.android.data.remote.TopupOrderRequest
import com.kaspaguy.kaspachat.android.data.remote.api
import com.kaspaguy.kaspachat.android.payment.KaspaNetwork
import com.kaspaguy.kaspachat.android.payment.KaspaPayment
import com.kaspaguy.kaspachat.android.security.Session
import kotlinx.coroutines.flow.Flow

/**
 * Plus and pay-as-you-go top-ups. Each order gets its own keyless payment-covenant address from the relay (SC-0018);
 * the relay watches it, settles the 25/75 split once the full amount is there and credits the order's account. The
 * app polls the order until then, like the web app's `ordersTick`.
 */
class PaymentRepository(
    private val relay: RelayApi,
    private val accounts: AccountRepository,
    private val session: Session,
    private val db: DatabaseHolder,
) {
    @Volatile private var cachedConfig: ConfigDto? = null

    suspend fun config(refresh: Boolean = false): ConfigDto =
        cachedConfig?.takeIf { !refresh } ?: api { relay.config() }.also { cachedConfig = it }

    suspend fun network(): KaspaNetwork = KaspaNetwork.fromConfig(config().network)

    fun orders(): Flow<List<OrderEntity>> = db.state.orders()
    fun order(id: String): Flow<OrderEntity?> = db.state.order(id)

    suspend fun checkName(name: String): NameCheck = api { relay.checkName(name) }

    suspend fun orderTopup(kas: Int): OrderEntity {
        val sompi = KaspaPayment.paygSompi(kas)
        val net = network()
        return accounts.withClaim { index, claim ->
            val r = api { relay.orderTopup(TopupOrderRequest(kas, claim)) }
            check(r.amount == sompi) { "The relay asked for a different amount; nothing was ordered." }
            save(r, index, "topup", net)
        }
    }

    /** Plus at the live registry price (about 100 KAS a month); the order's own amount is what gets paid. */
    suspend fun orderPlus(name: String, months: Int = 1): OrderEntity {
        require(months in 1..12)
        val net = network()
        val owner = session.ownerHex
        return accounts.withClaim { index, claim ->
            val r = api { relay.orderPlus(PlusOrderRequest(name, owner, months, claim)) }
            save(r, index, if (r.kind == "claim") "claim" else "plus", net)
        }
    }

    private suspend fun save(r: OrderCreated, index: Int, kind: String, net: KaspaNetwork): OrderEntity {
        KaspaPayment.paymentUri(r.address, r.amount, net) // refuses an address that isn't valid on this network
        val o = OrderEntity(
            id = r.order, claimIndex = index, kind = kind, name = r.name, months = r.months ?: 1,
            amountSompi = r.amount, address = r.address, status = "pending", created = System.currentTimeMillis(),
        )
        db.state.upsertOrder(o)
        return o
    }

    suspend fun paymentUri(o: OrderEntity): String = KaspaPayment.paymentUri(o.address, o.amountSompi, network())

    /** Testnet only (the relay refuses it elsewhere): the Kaspaguy faucet pays the order. */
    suspend fun testPay(id: String) {
        api { relay.testPay(id) }
    }

    /** One round over the orders that can still change: open ones, and settled ones for 31 days (late payments, SC-0024). */
    suspend fun pollOrders() {
        val now = System.currentTimeMillis()
        for (o in db.state.ordersNow()) {
            val open = o.status == "pending" || o.status == "paid"
            val recent = now - o.created < 31 * DAY_MS && now - o.extraChecked > 10 * 60_000
            if (open || recent) runCatching { pollOrder(o) }
        }
    }

    suspend fun pollOrder(id: String): OrderEntity? = db.state.ordersNow().find { it.id == id }?.let { pollOrder(it) }

    private suspend fun pollOrder(o: OrderEntity): OrderEntity {
        val r = api { relay.order(o.id) }
        val next = o.copy(status = r.status, error = r.error, extraSompi = r.extraSompi, extraChecked = System.currentTimeMillis())
        if (r.extraSompi > 0) adoptAccount(AccountEntity(o.claimIndex, extra = true, kind = "topup"))
        if (r.status == "done" && o.status != "done") {
            adoptAccount(AccountEntity(o.claimIndex, extra = false, kind = if (o.kind == "topup") "topup" else "plus"))
            if ((o.kind == "plus" || o.kind == "claim") && o.name != null) {
                db.state.upsertName(NameEntity(o.name, null, 0))
                db.state.put(KvEntity(AccountRepository.KEY_NAME, o.name))
                runCatching { accounts.refreshName(o.name) }
            }
        }
        db.state.upsertOrder(next)
        return next
    }

    private suspend fun adoptAccount(a: AccountEntity) {
        val dto = runCatching { api { relay.account(AccountRequest(accounts.accountSecretHex(a))) } }.getOrNull() ?: return
        db.state.insertAccount(a.copy(kind = dto.kind, credits = dto.credits))
        db.state.setCredits(a.claimIndex, a.extra, dto.credits)
    }

    private companion object {
        const val DAY_MS = 86_400_000L
    }
}
