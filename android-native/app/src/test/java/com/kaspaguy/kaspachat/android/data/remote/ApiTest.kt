package com.kaspaguy.kaspachat.android.data.remote

import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** The relay/indexer paths and bodies, as relay/src/index.ts and indexer/src/index.ts expect them. */
class ApiTest {
    private val server = MockWebServer()

    @Before fun start() = server.start()
    @After fun stop() = server.close()

    private val origin get() = server.url("/").toString()

    @Test fun topupOrderAndStatus() = runTest {
        server.enqueue(MockResponse.Builder().body("""{"order":"ab12","claim":"${"c".repeat(64)}","address":"kaspatest:pqq","amount":3500000000}""").build())
        server.enqueue(MockResponse.Builder().body("""{"order":"ab12","kind":"topup","status":"paid","amount":3500000000,"address":"kaspatest:pqq","txids":["t1"],"extraSompi":0,"months":1}""").build())
        val relay = Network.relay(origin)
        val created = relay.orderTopup(TopupOrderRequest(35, "c".repeat(64)))
        assertEquals(3_500_000_000L, created.amount)
        val req = server.takeRequest()
        assertEquals("/api/relay/v1/topup/order", req.url.encodedPath)
        assertEquals("""{"kas":35,"claim":"${"c".repeat(64)}"}""", req.body!!.utf8())
        assertNull(req.headers["authorization"])

        assertEquals("paid", relay.order("ab12").status)
        assertEquals("/api/relay/v1/order/ab12", server.takeRequest().url.encodedPath)
    }

    @Test fun relayErrorMessageSurfaces() = runTest {
        server.enqueue(MockResponse.Builder().code(409).body("""{"error":"account secret already in use"}""").build())
        try {
            api { Network.relay(origin).orderTopup(TopupOrderRequest(20, "d".repeat(64))) }
            fail()
        } catch (e: ApiError) {
            assertEquals(409, e.status)
            assertEquals("account secret already in use", e.message)
        }
    }

    @Test fun indexerPaths() = runTest {
        server.enqueue(MockResponse.Builder().body("""{"bucket":7,"roots":[],"entries":[{"name":"kvabc","owner":"00","expiry":0,"shard":1}]}""").build())
        val r = Network.indexer(origin).registryBucket(7)
        assertEquals("kvabc", r.entries.single().name)
        assertEquals("/api/index/v1/registry/bucket/7", server.takeRequest().url.encodedPath)
    }
}
