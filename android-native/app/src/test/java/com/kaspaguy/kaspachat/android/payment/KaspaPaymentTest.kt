package com.kaspaguy.kaspachat.android.payment

import com.google.zxing.BinaryBitmap
import com.google.zxing.LuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigDecimal

class KaspaPaymentTest {
    // A payment-covenant deposit address the testnet relay handed out (P2SH, `p…`), and a mainnet P2PK address.
    private val testnetAddr = "kaspatest:pr4tqawyks9shpdetgd968vs5wjaltfx9a67wk5ss70mx42eytjlu80xx99vq"
    private val mainnetAddr = "kaspa:qqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7u4jhsajr"

    @Test fun premiumHundredKasIsTenBillionSompi() {
        assertEquals(10_000_000_000L, KaspaPayment.kasToSompi(100))
        assertEquals(10_000_000_000L, KaspaPayment.kasToSompi(BigDecimal("100.00000000")))
    }

    @Test fun oneSompiAndFractions() {
        assertEquals(1L, KaspaPayment.kasToSompi(BigDecimal("0.00000001")))
        assertEquals(2_050_000_000L, KaspaPayment.kasToSompi(BigDecimal("20.5")))
    }

    @Test fun refusesToRoundMoney() {
        assertThrows(ArithmeticException::class.java) { KaspaPayment.kasToSompi(BigDecimal("1.000000001")) }
        assertThrows(IllegalArgumentException::class.java) { KaspaPayment.kasToSompi(BigDecimal("-1")) }
    }

    @Test fun formatsKasPlainWithoutTrailingZeros() {
        assertEquals("100", KaspaPayment.formatKas(10_000_000_000L))
        assertEquals("20.5", KaspaPayment.formatKas(2_050_000_000L))
        assertEquals("0.00000001", KaspaPayment.formatKas(1L))
        assertEquals("1234.56789012", KaspaPayment.formatKas(123_456_789_012L))
    }

    @Test fun formatAndParseRoundTripEverySliderValue() {
        for (kas in KaspaPayment.PAYG_MIN_KAS..KaspaPayment.PAYG_MAX_KAS) {
            val sompi = KaspaPayment.paygSompi(kas)
            assertEquals(kas * 100_000_000L, sompi)
            assertEquals(sompi, KaspaPayment.kasToSompi(BigDecimal(KaspaPayment.formatKas(sompi))))
        }
    }

    @Test fun paygBounds() {
        assertThrows(IllegalArgumentException::class.java) { KaspaPayment.paygSompi(19) }
        assertThrows(IllegalArgumentException::class.java) { KaspaPayment.paygSompi(51) }
    }

    @Test fun premiumUriOnMainnet() {
        assertEquals("$mainnetAddr?amount=100", KaspaPayment.paymentUri(mainnetAddr, 10_000_000_000L, KaspaNetwork.MAINNET))
    }

    @Test fun paygUriOnTestnet() {
        assertEquals("$testnetAddr?amount=35", KaspaPayment.paymentUri(testnetAddr, 3_500_000_000L, KaspaNetwork.TESTNET))
    }

    @Test fun addsTheNetworkPrefixWhenMissing() {
        val bare = testnetAddr.substringAfter(':')
        assertEquals("$testnetAddr?amount=20", KaspaPayment.paymentUri(bare, 2_000_000_000L, KaspaNetwork.TESTNET))
    }

    @Test fun refusesWrongNetworkBadChecksumAndZeroAmount() {
        assertThrows(IllegalArgumentException::class.java) { KaspaPayment.paymentUri(testnetAddr, 1L, KaspaNetwork.MAINNET) }
        val typo = testnetAddr.dropLast(1) + "r"
        assertThrows(IllegalArgumentException::class.java) { KaspaPayment.paymentUri(typo, 1L, KaspaNetwork.TESTNET) }
        assertThrows(IllegalArgumentException::class.java) { KaspaPayment.paymentUri(testnetAddr, 0L, KaspaNetwork.TESTNET) }
    }

    @Test fun addressChecksum() {
        assertTrue(KaspaAddress.isValid(testnetAddr))
        assertTrue(KaspaAddress.isValid(mainnetAddr))
        assertFalse(KaspaAddress.isValid(mainnetAddr.replace("kaspa:", "kaspatest:")))
        assertFalse(KaspaAddress.isValid("kaspa:"))
        assertFalse(KaspaAddress.isValid("kaspa:qqqb"))
    }

    @Test fun networkFromRelayConfig() {
        assertEquals(KaspaNetwork.TESTNET, KaspaNetwork.fromConfig("testnet-10"))
        assertEquals(KaspaNetwork.MAINNET, KaspaNetwork.fromConfig("mainnet"))
    }

    @Test fun qrCodeDecodesToTheExactUri() {
        val uri = KaspaPayment.paymentUri(testnetAddr, 10_000_000_000L, KaspaNetwork.TESTNET)
        val m = QrCode.encode(uri)
        val scale = 4
        val w = m.width * scale
        val source = object : LuminanceSource(w, w) {
            override fun getRow(y: Int, row: ByteArray?): ByteArray = ByteArray(w) { x -> lum(x, y) }
            override fun getMatrix(): ByteArray = ByteArray(w * w) { lum(it % w, it / w) }
            private fun lum(x: Int, y: Int): Byte = if (m.get(x / scale, y / scale)) 0 else -1
        }
        assertEquals(uri, QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source))).text)
    }
}
