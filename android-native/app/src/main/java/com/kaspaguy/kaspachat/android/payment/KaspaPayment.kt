package com.kaspaguy.kaspachat.android.payment

import java.math.BigDecimal

/** Network prefixes of Kaspa addresses (rusty-kaspa `Prefix`). */
enum class KaspaNetwork(val prefix: String) {
    MAINNET("kaspa"), TESTNET("kaspatest"), DEVNET("kaspadev"), SIMNET("kaspasim");

    companion object {
        /** The relay's `/v1/config` `network` ("mainnet", "testnet-10", …). */
        fun fromConfig(network: String): KaspaNetwork = when {
            network.startsWith("mainnet") -> MAINNET
            network.startsWith("testnet") -> TESTNET
            network.startsWith("devnet") -> DEVNET
            network.startsWith("simnet") -> SIMNET
            else -> throw IllegalArgumentException("unknown network")
        }
    }
}

/**
 * Payment amounts and the wallet URI shown as a QR code.
 *
 * All arithmetic is in sompi (Long, 1 KAS = 100,000,000 sompi). The URI follows the BIP-21 shape Kaspa wallets
 * (Kaspium, KaspaCom, the web wallet) read: `kaspa:<address>?amount=<KAS as a decimal>`, the same as the KaspaChat
 * web app (app/src/ui/App.tsx). The address already carries its network prefix (`kaspatest:` on testnet).
 */
object KaspaPayment {
    const val SOMPI_PER_KAS = 100_000_000L
    const val PAYG_MIN_KAS = 20
    const val PAYG_MAX_KAS = 50

    const val EXACT_AMOUNT_WARNING = "Send the exact amount in one transaction. Do not send partial payments."

    /** Exact KAS → sompi; refuses negative amounts and more than 8 decimals instead of rounding money. */
    fun kasToSompi(kas: BigDecimal): Long {
        require(kas.signum() >= 0) { "negative amount" }
        return kas.movePointRight(8).longValueExact()
    }

    fun kasToSompi(kas: Int): Long = kasToSompi(BigDecimal(kas))

    /** "100", "20.5", "0.00000001" — never exponent notation, never trailing zeros. */
    fun formatKas(sompi: Long): String {
        require(sompi >= 0) { "negative amount" }
        return BigDecimal.valueOf(sompi, 8).stripTrailingZeros().toPlainString()
    }

    fun paygSompi(kas: Int): Long {
        require(kas in PAYG_MIN_KAS..PAYG_MAX_KAS) { "pay-as-you-go is $PAYG_MIN_KAS-$PAYG_MAX_KAS KAS" }
        return kasToSompi(kas)
    }

    /**
     * The QR payload. The address must be a valid address on [network] (checksum included): a deposit address from
     * the relay that fails this is never shown, because a wrong address loses the money.
     */
    fun paymentUri(address: String, sompi: Long, network: KaspaNetwork): String {
        require(sompi > 0) { "amount must be positive" }
        val full = if (':' in address) address.lowercase() else "${network.prefix}:${address.lowercase()}"
        require(full.substringBefore(':') == network.prefix) { "address is for another network" }
        require(KaspaAddress.isValid(full)) { "invalid Kaspa address" }
        return "$full?amount=${formatKas(sompi)}"
    }
}

/** Kaspa's CashAddr-style address checksum (rusty-kaspa `addresses::bech32`). */
object KaspaAddress {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val GEN = longArrayOf(0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)

    fun isValid(address: String): Boolean {
        val prefix = address.substringBefore(':', "")
        val data = address.substringAfter(':', "")
        if (prefix.isEmpty() || prefix.any { it !in 'a'..'z' } || data.length < 9) return false
        if (data.any { CHARSET.indexOf(it) < 0 }) return false
        val values = prefix.map { it.code and 31 } + 0 + data.map { CHARSET.indexOf(it) }
        return polymod(values) == 0L
    }

    private fun polymod(values: List<Int>): Long {
        var c = 1L
        for (d in values) {
            val c0 = c ushr 35
            c = ((c and 0x07ffffffffL) shl 5) xor d.toLong()
            for (i in GEN.indices) if ((c0 shr i) and 1L == 1L) c = c xor GEN[i]
        }
        return c xor 1L
    }
}
