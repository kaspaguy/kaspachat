package com.kaspaguy.kaspachat.android.data.remote

import com.kaspaguy.kaspachat.android.BuildConfig
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import retrofit2.HttpException
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import java.util.concurrent.TimeUnit

// The two public services, as the web app reaches them (app/src/lib/api.ts): `<origin>/api/relay` (Kaspaguy's relay
// and doorman, relay/src/index.ts) and `<origin>/api/index` (any indexer, indexer/src/index.ts).

@Serializable
data class ConfigDto(
    val network: String,
    val tokenPublicKey: String,
    val nameBits: Int,
    val coverBits: Int,
    val welcome: Int,
    val plusPrice: Long,
    val minTopup: Long,
    val msgFee: Long,
    val creditsPerMonth: Int,
    val tokenDays: Int,
)

@Serializable data class PowChallenge(val challenge: String, val bits: Int)
@Serializable data class PowSolution(val challenge: String, val nonce: String)
@Serializable data class DefaultNameRequest(val owner: String, val n: Int, val pow: PowSolution, val claim: String)
@Serializable data class DefaultNameResponse(val name: String, val txid: String? = null, val account: String, val credits: Int)
@Serializable data class NameCheck(val name: String, val available: Boolean, val lapsed: Boolean = false, val reason: String? = null)
@Serializable data class PlusOrderRequest(val name: String, val owner: String, val months: Int, val claim: String)
@Serializable data class TopupOrderRequest(val kas: Int, val claim: String)

@Serializable
data class OrderCreated(val order: String, val kind: String? = null, val claim: String, val address: String, val amount: Long, val name: String? = null, val months: Int? = null)

@Serializable
data class OrderStatus(
    val order: String,
    val kind: String,
    val status: String,
    val name: String? = null,
    val months: Int? = null,
    val amount: Long,
    val address: String,
    val txids: List<String> = emptyList(),
    val error: String? = null,
    val extraSompi: Long = 0,
)

@Serializable data class AccountRequest(val account: String)
@Serializable data class AccountDto(val kind: String, val credits: Int, val info: String, val months: Int, val monthIdx: Int, val start: Long, val name: String? = null)
@Serializable data class PayloadRequest(val payload: String)
@Serializable data class TxResponse(val txid: String? = null)

@Serializable data class RegistryEntry(val name: String? = null, val owner: String? = null, val expiry: Long = 0)
@Serializable data class RegistryEntries(val entries: List<RegistryEntry> = emptyList())
@Serializable data class BundleRow(val tag: String, val p: String, val t: Long)
@Serializable data class BundleBucket(val bucket: Int, val bundles: List<BundleRow>)
@Serializable data class Tip(val daa: Long, val synced: Boolean, val now: Long)

interface RelayApi {
    @GET("v1/config") suspend fun config(): ConfigDto
    @GET("v1/pow") suspend fun pow(): PowChallenge
    @POST("v1/names/default") suspend fun registerDefault(@Body r: DefaultNameRequest): DefaultNameResponse
    @GET("v1/names/check/{name}") suspend fun checkName(@Path("name") name: String): NameCheck
    @POST("v1/plus/order") suspend fun orderPlus(@Body r: PlusOrderRequest): OrderCreated
    @POST("v1/topup/order") suspend fun orderTopup(@Body r: TopupOrderRequest): OrderCreated
    @GET("v1/order/{id}") suspend fun order(@Path("id") id: String): OrderStatus
    @POST("v1/order/testpay/{id}") suspend fun testPay(@Path("id") id: String, @Body empty: Map<String, String> = emptyMap()): TxResponse
    @POST("v1/account") suspend fun account(@Body r: AccountRequest): AccountDto
    @POST("v1/bundle") suspend fun publishBundle(@Body r: PayloadRequest): TxResponse
}

interface IndexerApi {
    @GET("v1/registry/bucket/{b}") suspend fun registryBucket(@Path("b") bucket: Int): RegistryEntries
    @GET("v1/registry/owner/{owner}") suspend fun registryOwner(@Path("owner") owner: String): RegistryEntries
    @GET("v1/bundles/{b}") suspend fun bundles(@Path("b") bucket: Int): BundleBucket
    @GET("v1/tip") suspend fun tip(): Tip
}

/** An HTTP error with the service's own message (`{"error": "..."}`), which never contains secrets. */
class ApiError(val status: Int, message: String) : Exception(message)

private val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

suspend fun <T> api(call: suspend () -> T): T = try {
    call()
} catch (e: HttpException) {
    val msg = runCatching {
        json.parseToJsonElement(e.response()?.errorBody()?.string().orEmpty()).jsonObject["error"]?.jsonPrimitive?.content
    }.getOrNull()
    throw ApiError(e.code(), msg ?: "service unavailable (${e.code()})")
}

object Network {
    // No logging interceptor, by design: request bodies carry account secrets and owner keys.
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(90, TimeUnit.SECONDS) // a free-name registration waits for its chain transaction
        .addInterceptor { chain ->
            val b = chain.request().newBuilder().header("cache-control", "no-store")
            if (BuildConfig.API_AUTH.isNotEmpty()) b.header("authorization", "Basic ${BuildConfig.API_AUTH}")
            chain.proceed(b.build())
        }
        .build()

    private fun retrofit(base: String) = Retrofit.Builder()
        .baseUrl(base)
        .client(client)
        .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
        .build()

    fun relay(origin: String = BuildConfig.API_ORIGIN): RelayApi = retrofit("${origin.trimEnd('/')}/api/relay/").create(RelayApi::class.java)
    fun indexer(origin: String = BuildConfig.API_ORIGIN): IndexerApi = retrofit("${origin.trimEnd('/')}/api/index/").create(IndexerApi::class.java)
}
