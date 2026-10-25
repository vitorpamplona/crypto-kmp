# crypto-kmp

Cryptographic primitives for Kotlin Multiplatform: JVM, Android, iOS, macOS, Linux, JavaScript
and Wasm. The library depends on nothing but the Kotlin stdlib. It uses the platform's implementation where
one is fast and available (JCA on the JVM and Android, CommonCrypto on Apple) and pure Kotlin
everywhere else. The AES and GHASH cores are constant-time.

It is the crypto layer of [Quartz](https://github.com/vitorpamplona/amethyst/tree/main/quartz)
(the Nostr library behind Amethyst) and of [quic-kmp](https://github.com/vitorpamplona/quic-kmp).

## Install

```kotlin
dependencies {
    implementation("com.vitorpamplona.crypto:crypto:<version>")
}
```

| Requirement | |
|---|---|
| JVM | Java 17 |
| Android | minSdk 26 |
| Apple | iosArm64, iosSimulatorArm64, macosArm64 |
| Linux | linuxX64 |
| Web | js and wasmJs, in browsers and Node.js: any runtime with Web Crypto's `crypto.getRandomValues` (Node.js 19+, Deno and Bun too) |

## What's inside

| Primitive | Package | JVM / Android | Apple | Linux | JS / Wasm |
|---|---|---|---|---|---|
| SHA-256 one-shot (`sha256`, `sha256Into`) | `sha2` | JCA (pooled) | CommonCrypto | Kotlin | Kotlin |
| `DigestInstance` (SHA-1, SHA-256, SHA-512, RIPEMD-160), streaming | `digest` | JCA (SHA), Kotlin (RIPEMD-160) | CommonCrypto (SHA), Kotlin (RIPEMD-160) | Kotlin | Kotlin |
| RIPEMD-160 (`RIPEMD160Digest`), Keccak (`KeccakDigest`) | `digest` | Kotlin | Kotlin | Kotlin | Kotlin |
| HMAC-SHA1 / HMAC-SHA256 / HMAC-SHA512 (`MacInstance`) | `mac` | JCA | CommonCrypto | Kotlin | Kotlin |
| HKDF (RFC 5869) and TLS 1.3 `expandLabel` | `kdf` | on `MacInstance` | on `MacInstance` | on `MacInstance` | on `MacInstance` |
| AES-GCM (any nonce length, 128-bit tag) | `aes` | JCA | CommonCrypto AES-CTR, Kotlin GHASH (constant-time) | Kotlin, constant-time | Kotlin, constant-time |
| AES-CBC with PKCS#7 | `aes` | JCA | CommonCrypto | Kotlin, constant-time | Kotlin, constant-time |
| ChaCha20, Poly1305 | `chacha` | Kotlin | Kotlin | Kotlin | Kotlin |
| ChaCha20-Poly1305, XChaCha20-Poly1305 | `chacha` | JCA where it is native or vectorised, else Kotlin | Kotlin | Kotlin | Kotlin |
| X25519, Ed25519 | `curve25519` | Kotlin (Ed25519 hashes with JCA) | Kotlin | Kotlin | Kotlin |
| Secure random (`RandomInstance`) | `random` | `java.security.SecureRandom` | `SecRandomCopyBytes` | `getrandom(2)` | `crypto.getRandomValues` |

Packages are under `com.vitorpamplona.crypto`.

On the JVM and Android, ChaCha20-Poly1305 (and XChaCha20-Poly1305, which runs on it) calls JCA
only where JCA is faster: Android's BoringSSL on API 28+, a bundled Conscrypt, or SunJCE when
HotSpot compiles both ChaCha20 and Poly1305 to vector instructions (JDK 20+ on a CPU with them).
Java 17's SunJCE is pure Java and slower than the Kotlin code, so there the Kotlin code runs.
The provider is picked by name and checked against the Kotlin output once, at first use.

On the web everything but the random numbers is Kotlin: Web Crypto's digests and ciphers are
async-only (they return a `Promise`), so they can't sit behind this synchronous API. Kotlin/JS has
no 64-bit integers and emulates `Long`, which makes the 64-bit arithmetic of SHA-512, GHASH,
Poly1305 and Curve25519 slower there than anywhere else: an X25519 or Ed25519 operation takes tens
of milliseconds in Node.js. Kotlin/Wasm runs 64-bit arithmetic natively, so prefer `wasmJs` where
those are on a hot path. The emulated `Long` multiply also branches on its operands, so every
product of secrets here goes through a branch-free multiply on Kotlin/JS instead.

## Usage

```kotlin
import com.vitorpamplona.crypto.aes.AESGCM
import com.vitorpamplona.crypto.chacha.ChaCha20Poly1305
import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.crypto.kdf.Hkdf
import com.vitorpamplona.crypto.mac.MacInstance
import com.vitorpamplona.crypto.random.RandomInstance
import com.vitorpamplona.crypto.sha2.sha256

val digest = sha256("hello".encodeToByteArray())

val macKey = RandomInstance.bytes(32)
val mac = MacInstance("HmacSHA256", macKey)
mac.update(message)
val tag = mac.doFinal()

val hkdf = Hkdf() // HMAC-SHA256
val okm = hkdf.expand(hkdf.extract(ikm, salt), info, 42)

// One key per algorithm, and a fresh nonce for every message: never encrypt twice
// under the same key and nonce.
val aesKey = RandomInstance.bytes(32)
val aesNonce = RandomInstance.bytes(12)
val sealed = AESGCM(aesKey, aesNonce).encrypt(plaintext, aad) // ciphertext || 16-byte tag
val opened = AESGCM(aesKey, aesNonce).decryptOrNull(sealed, aad) // null when the tag doesn't verify

val chachaKey = RandomInstance.bytes(32)
val chachaNonce = RandomInstance.bytes(12)
val boxed = ChaCha20Poly1305.encrypt(plaintext, aad, chachaNonce, chachaKey)
val unboxed = ChaCha20Poly1305.decryptOrNull(boxed, aad, chachaNonce, chachaKey)

val alice = X25519.generateKeyPair()
val bob = X25519.generateKeyPair()
val shared = X25519.dh(alice.privateKey, bob.publicKey)

val signer = Ed25519.generateKeyPair()
val signature = Ed25519.sign(message, signer.privateKey)
check(Ed25519.verify(message, signature, signer.publicKey))
```

Every platform accepts and rejects the same inputs, with the same exceptions:

- A wrong key, nonce or IV size throws `IllegalArgumentException`, from the constructor or call
  that receives it.
- `decrypt` throws `IllegalArgumentException` when a tag doesn't verify, padding is bad or the
  input is too short (on the JVM, JCA's exception is its `cause`). `decryptOrNull` returns `null`
  for exactly those cases and logs nothing.
- `DigestInstance` and `MacInstance` take the algorithms in the table above, by their JCA names
  (case-insensitive), and throw `IllegalArgumentException` for any other.

An `AESGCM` instance holds one key and one nonce, so it encrypts once: a second `encrypt` throws
`IllegalStateException` instead of reusing the nonce. Decrypt with it as often as needed. That
guard only sees one instance: two instances built from the same key and nonce still reuse it, so
draw a fresh random nonce (or a counter that never repeats under the key) for every message. The
default nonce is 16 random bytes. AES-CBC is not authenticated: pair it with a MAC
(encrypt-then-MAC), or its padding errors become a padding oracle.

`Ed25519.verify` follows RFC 8032 and additionally rejects non-canonical and small-order public
keys and `R` values, as libsodium does. `Ed25519.sign` derives the public key from the seed half
of the 64-byte private key and never trusts the stored half.

## Testing

Every primitive has known-answer vectors in `commonTest`, run on every platform: FIPS 180-4,
FIPS 197, NIST SP 800-38A (CBC) and the GCM specification's test cases, RFC 2202, RFC 4231,
RFC 5869, RFC 7748, RFC 8032, RFC 8439 (including the Poly1305 edge cases of Appendix A.3),
RFC 9001 (`expandLabel`), draft-irtf-cfrg-xchacha, the RIPEMD-160 and Keccak reference vectors.
On top of those, every platform runs Project Wycheproof's 2,674 vectors for AES-GCM, AES-CBC,
ChaCha20-Poly1305, XChaCha20-Poly1305, X25519, Ed25519, HMAC and HKDF: the counter wraps, odd
nonce sizes, modified tags, bad padding, low-order and non-canonical points and malleable
signatures that spec vectors miss (`scripts/wycheproof/generate.py` regenerates them). The web
targets run all of it in Node.js and in headless Chrome.
Each primitive also has negative tests (tampered tags, bad padding, wrong sizes, low-order and
non-canonical points), and JVM tests compare AES, ChaCha20-Poly1305, X25519, Ed25519, SHA and
HMAC with JCA on random inputs.

## Performance

[BENCHMARKS.md](BENCHMARKS.md) compares crypto-kmp with JCA and Bouncy Castle on the JVM, and with
noble, TweetNaCl and node:crypto on Node.js. In short: on the JVM it matches JCA where it wraps it
and beats Bouncy Castle on everything but Curve25519; Kotlin/Wasm beats noble on most operations;
Kotlin/JS is several times slower than noble, so prefer `wasmJs` on the web.

## Developer Setup

```bash
./gradlew installGitHook            # pre-commit (spotless) and pre-push (tests) hooks
./gradlew spotlessApply
./gradlew :crypto:jvmTest :crypto:testAndroidHostTest :crypto:linuxX64Test
./gradlew :crypto:jsTest :crypto:wasmJsTest        # Node.js and headless Chrome (jsNodeTest, wasmJsNodeTest for Node only)
./gradlew :crypto:compileAppleMainKotlinMetadata   # Apple code, compiled on any host
./gradlew :crypto:checkKotlinAbi    # public API matches crypto/api; updateKotlinAbi to accept a change
./gradlew :crypto:iosSimulatorArm64Test :crypto:macosArm64Test   # macOS only
```

## Versioning

Releases follow [semantic versioning](https://semver.org/): a breaking change to the public API
bumps the major version. Each release is tagged `v<version>` and listed on the
[releases page](https://github.com/vitorpamplona/crypto-kmp/releases). The public API is recorded
in `crypto/api/` and checked by `checkKotlinAbi`, so a change to it shows up in review.

## License

MIT, see [LICENSE](LICENSE). Ported code keeps its attribution in the source:

- The constant-time AES (`aes/AesBitsliced.kt`) and GHASH (`aes/Ghash.kt`) are ports of
  BearSSL's `aes_ct64` and `ghash_ctmul64`, Copyright (c) 2016 Thomas Pornin, MIT.
- `GeneralDigest`, `RIPEMD160Digest`, `KeccakDigest` and `Digest` are ports of Bouncy Castle's,
  Copyright (c) 2000-2024 The Legion of the Bouncy Castle Inc., MIT.
- Poly1305 follows Andrew Moon's poly1305-donna-32 (public domain / MIT).
- The test vectors in `crypto/src/commonTest/.../wycheproof/` are Project Wycheproof's,
  Copyright Google LLC, Apache License 2.0 (its `LICENSE` is next to them).
- The Curve25519 field and point arithmetic follow TweetNaCl and ref10 (both public domain).
