# KaspaChat for Android (native)

> **Paused (2026-10-24, Kaspaguy).** Phase 1 only: it has no chat screen. The KaspaChat app shipped on Android,
> iPhone, desktop and the web is the Capacitor one in `mobile/` + `app/`. Pick this up again only on Kaspaguy's word.

Native Kotlin/Jetpack Compose client for KaspaChat. It is separate from the Capacitor wrapper in `mobile/android`,
which it does not touch, and it installs side by side with it (application id `com.kaspaguy.kaspachat.android`).
Closed source, like the other apps (`LICENSING.md`).

**This build (phase 1)** covers onboarding (new 24-word phrase or restore), the Keystore- and passcode-sealed seed,
registering the free `@kv…` name and publishing the key bundle, credits, and the Top Up / Upgrade screen. That
screen shows a payment QR code and watches the order until it settles. Messaging comes next (see "Not in this
build").

## Layout

| Path | What |
|---|---|
| `core/` | Rust crate `kaspachat-core`: the JNI bridge to `../rust-impl` (the byte-exact Kaspaveil v1 implementation). It also holds the app-local crypto: BIP-39 generation, the claim secrets, the passcode layer of the vault (scrypt N=2^15 + AES-256-GCM, same as `protocol/src/vault.ts`) and the doorman's proof of work. The app does no cryptography of its own. |
| `app/src/main/java/.../core/NativeCore.kt` | The Kotlin side of the JNI bridge. |
| `.../payment/` | `KaspaPayment`: sompi maths, the wallet URI, Kaspa address checksum. `QrCode`: ZXing encoding. |
| `.../security/` | `SeedVault`: Keystore + passcode vault for the phrase. `Session`: the seed in memory only while unlocked; locking wipes it. |
| `.../data/local/` | Room on SQLCipher. The database key is derived from the seed at unlock, so the database only opens while unlocked. |
| `.../data/remote/` | Retrofit APIs for the relay (`/api/relay`) and the indexer (`/api/index`). |
| `.../domain/` | `AccountRepository` (name, bundle, credit accounts, restore) and `PaymentRepository` (orders, polling). |
| `.../ui/` | Compose screens: onboarding, unlock, home, top-up, payment. |
| `tools/device-check.sh` | Checks the app on a phone or emulator. |

The architecture is MVVM with repositories, and DI uses Koin. Koin needs no annotation processing, which avoids
Hilt's Gradle plugin on AGP 9.

## Setup

1. **JDK** 17 or newer (built here with 21).
2. **Android SDK**: platform `android-37`, build-tools 37, **NDK `30.0.16248370`**
   (`sdkmanager "platforms;android-37.0" "ndk;30.0.16248370"`).
3. **Rust** (stable) with the Android targets and cargo-ndk:
   ```sh
   rustup target add aarch64-linux-android x86_64-linux-android
   cargo install cargo-ndk --locked
   ```
   Every Gradle build cross-compiles `core/` into `app/src/main/jniLibs/` (arm64-v8a, x86_64). Unit tests also build
   it for the host. Pass `-PskipRust` to reuse libraries that are already built.
4. **`local.properties`** in `android-native/` (never committed):
   ```properties
   sdk.dir=/path/to/android-sdk
   # Testnet stack (default). Mainnet later: the production origin.
   kaspachat.apiOrigin=https://testnet.kaspachat.com
   # The testnet sits behind basic auth: base64 of user:password, the same value the web app's private
   # builds take as VITE_API_AUTH. Leave it out for an open server.
   kaspachat.apiAuth=
   # true for Play/App Store builds: these sell nothing in the app (Play billing policy), as in the web app's storeBuild.
   kaspachat.storeBuild=false
   ```

The app reaches the same endpoints as the web app (`app/src/lib/api.ts`): `<origin>/api/relay/v1/...` for the
relay/doorman and `<origin>/api/index/v1/...` for the indexer. Behind nginx these are the relay on 127.0.0.1:5511
and the indexer on its own port. The network (testnet-10 or mainnet) comes from the relay's `GET /v1/config`, so
address prefixes are checked against what the server says.

## Build

```sh
cd android-native
./gradlew :app:assembleDebug          # app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:assembleRelease        # minified with R8; Log calls stripped; sign before installing
```

Opening `android-native/` in Android Studio works as well (the Rust build runs as a Gradle task).

## Tests

```sh
(cd core && cargo test)               # Rust core vs protocol/vectors/v1.json, Node-computed claim/scrypt values
./gradlew :app:testDebugUnitTest      # JVM: QR/URI/sompi, the JNI bridge (host build) vs the vectors, API paths
./gradlew :app:connectedDebugAndroidTest   # on a device: Keystore vault, passcode throttle, SQLCipher, lock
```

`KaspaPaymentTest` covers the QR code logic:
- KAS to sompi is exact: 100 KAS = 10,000,000,000 sompi and 1 sompi = 0.00000001 KAS. Amounts with more than 8
  decimals are refused rather than rounded.
- KAS is formatted without exponents or trailing zeros.
- Every pay-as-you-go value from 20 to 50 KAS round-trips, and values outside that range are refused.
- The URI has the form `kaspa:<address>?amount=<KAS>` (with `kaspatest:` on testnet), and the network prefix is
  added when the address lacks one.
- An address for the wrong network, a bad address checksum or a zero amount is refused.
- A generated QR code decodes back to the exact URI with ZXing's reader.

### Why the QR amount is in KAS, not sompi

Kaspa wallets read the BIP-21 shape: `amount` is a decimal number of KAS, and the web app does the same
(`app/src/ui/App.tsx`). Writing sompi there (`?amount=10000000000`) would make a wallet pre-fill ten billion KAS.
The app does all its arithmetic in sompi (`Long`) and formats KAS only when it builds the URI.

## Checking on a device

Run `tools/device-check.sh` with one phone or emulator connected (`adb devices`). It runs the unit tests, then the
device tests, installs the debug build, launches it, and fails if anything sensitive-looking shows up in Logcat
under the app's pid. The build machine has no KVM, so an emulator has to run on a desktop (Android Studio, any
x86_64 or arm64 image, API 28 or later). A physical phone with USB debugging works too.

Then walk through these by hand:

1. **New account.** The phrase screen shows 24 words. Take a screenshot: it must come out black or be refused
   (FLAG_SECURE), and the recents thumbnail must be blank. Then confirm 3 words, set an 8+ character passcode
   (7 characters must be refused), and watch the free-name progress ("Solving the anti-spam puzzle…" takes a few
   seconds). Home shows `@kv…` and 10 credits.
2. **Lock and unlock.** Tap Lock, then try a wrong passcode 5 times: the next try must ask you to wait. Then unlock
   with the right one. Background the app for more than 5 minutes: it reopens on the unlock screen.
3. **Top up.** Choose 20–50 KAS and Pay.
   - The payment screen must show the red notice: *Send the exact amount in one transaction. Do not send partial
     payments.*
   - Scan the QR code with Kaspium or KaspaCom (or any QR reader to see the text). The wallet must fill in the
     address and the exact amount.
   - "Open in wallet app" hands the same URI to an installed wallet.
   - On testnet, the "pay with the test faucet" button pays the order. Within a minute the status goes from
     "Waiting for payment" through "Paid, confirming" to "Done", and the credits on Home go up by about
     `kas × 0.75 / 0.00421`.
4. **Plus.** Enter a launch-shape name (e.g. `bob-123`). The price is the live registry price (100 tKAS on
   testnet). The flow is the same as a top-up. Once done, Home shows the Plus name.
5. **Restore.** Remove the account on the unlock screen, choose Restore and enter the phrase. The same name, the
   credits and any Plus name come back.

Steps 1, 3, 4 and 5 make real testnet registrations and orders on the shared stack.

## Security rules, and where they are enforced

- **No plaintext keys on disk.** Only the sealed phrase is stored (`seed.vault` in no-backup storage): AES-GCM
  under a non-exportable Keystore key (StrongBox when the phone has one) around AES-GCM under scrypt(passcode).
  The seed, owner key, prekeys, claim secrets and database key are all derived at unlock. Byte-array copies are
  wiped when no longer needed, and on lock. The phrase is a `String` only while it is on screen during sign-up or
  restore: the JVM can't wipe those. Backup and device transfer are off (`allowBackup=false`, extraction
  rules exclude everything).
- **Passcode** of at least 8 characters. 5 free tries, then a doubling wait (capped at an hour) that survives
  restarts.
- **Screenshots.** `SecureWindow()` sets FLAG_SECURE on the phrase, confirm and restore screens. Protected chats
  will use the same call.
- **No logging.** The app has no `Log` calls and no OkHttp logging interceptor (request bodies carry secrets). R8
  strips `android.util.Log` in release builds. Native errors carry only an error kind, never input.
- **Payments.** The deposit address from the relay must pass the Kaspa checksum and match the server's network
  before it is shown. The top-up amount the relay returns must equal what was asked for, or nothing is shown.

## Not in this build (next phases)

- **Messaging:** chat list and chat screen, first contact, the ratchet, the tag-bucket fetch and the outbox. The
  pieces are in `rust-impl` (`first_contact`, `session`, `buckets`) and need JNI wrappers plus a session store.
- **Blind tokens** (RFC 9497 POPRF, ristretto255-SHA512) for paying sends through the relay. `rust-impl` doesn't
  have POPRF; the audited `voprf` crate does and goes into `core/`. Until then the app shows the credits held on
  the relay accounts.
- **The 30-hour timer and the screenshot notice:** the chat's settings, and the Android 14+ screen-capture
  callback in protected chats.
- **The 0-credit outbox:** sending with no credits warns, queues, and sends after a top-up.
- **Background sync:** WorkManager polling the indexer. The database only opens while unlocked, so this needs a
  decision on what may be read while the app is locked.
- **Real icon** (still the placeholder; the candidates are in `branding/candidates/`).
