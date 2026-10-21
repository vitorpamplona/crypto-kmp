# crypto-kmp

Cryptographic primitives for Kotlin Multiplatform: JVM, Android, iOS, macOS and Linux. The
library depends on nothing but the Kotlin stdlib. It uses the platform's implementation where
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

## What's inside

| Primitive | Package | JVM / Android | Apple | Linux |
|---|---|---|---|---|
| SHA-256 one-shot (`sha256`, `sha256Into`) | `sha2` | JCA (pooled) | CommonCrypto | Kotlin |
| SHA-1 / SHA-256 / SHA-512 streaming (`ShaDigest`) | `sha2` | Kotlin | Kotlin | Kotlin |
| `DigestInstance` (SHA-256, SHA-1; RIPEMD-160 off the JVM) | `digest` | JCA | CommonCrypto (SHA), Kotlin (RIPEMD-160) | Kotlin |
| RIPEMD-160 (`RIPEMD160Digest`), Keccak | `digest` | Kotlin | Kotlin | Kotlin |
| HMAC-SHA256 / HMAC-SHA512 (`MacInstance`) | `mac` | JCA | CommonCrypto | Kotlin |
| HKDF (RFC 5869) and TLS 1.3 `expandLabel` | `kdf` | on `MacInstance` | on `MacInstance` | on `MacInstance` |
| AES-GCM (any nonce length, 128-bit tag) | `aes` | JCA | Kotlin, constant-time | Kotlin, constant-time |
| AES-CBC with PKCS#7 | `aes` | JCA | CommonCrypto | Kotlin, constant-time |
| ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305 | `chacha` | Kotlin | Kotlin | Kotlin |
| X25519, Ed25519 | `curve25519` | Kotlin (Ed25519 hashes with JCA) | Kotlin | Kotlin |
| Secure random (`RandomInstance`) | `random` | `SecureRandom` | `SecRandomCopyBytes` | `/dev/urandom` |

Packages are under `com.vitorpamplona.crypto`.

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

val mac = MacInstance("HmacSHA256", key)
mac.update(message)
val tag = mac.doFinal()

val hkdf = Hkdf() // HMAC-SHA256
val okm = hkdf.expand(hkdf.extract(ikm, salt), info, 42)

val key = RandomInstance.bytes(32)
val nonce = RandomInstance.bytes(12)
val sealed = AESGCM(key, nonce).encrypt(plaintext, aad) // ciphertext || 16-byte tag
val opened = AESGCM(key, nonce).decryptOrNull(sealed) // null when the tag doesn't verify

val boxed = ChaCha20Poly1305.encrypt(plaintext, aad, nonce, key)

val alice = X25519.generateKeyPair()
val bob = X25519.generateKeyPair()
val shared = X25519.dh(alice.privateKey, bob.publicKey)

val signer = Ed25519.generateKeyPair()
val signature = Ed25519.sign(message, signer.privateKey)
check(Ed25519.verify(message, signature, signer.publicKey))
```

`decryptOrNull` returns `null` on a bad tag, padding or key size and logs nothing; `decrypt`
throws `IllegalArgumentException` instead (or JCA's `GeneralSecurityException` on the JVM).

On the JVM, `DigestInstance` is `MessageDigest`, and the default JDK has no RIPEMD-160: use
`RIPEMD160Digest` directly there.

## Testing

Every primitive has known-answer vectors in `commonTest` (FIPS 180-4, FIPS 197, RFC 4231,
RFC 5869, RFC 7748, RFC 8032, RFC 8439, and AES-GCM/CBC vectors generated with OpenSSL), run on
every platform, plus JVM tests that compare the Kotlin code with JCA on random inputs.

## Developer Setup

```bash
./gradlew installGitHook            # pre-commit (spotless) and pre-push (tests) hooks
./gradlew spotlessApply
./gradlew :crypto:jvmTest :crypto:testAndroidHostTest :crypto:linuxX64Test
./gradlew :crypto:compileAppleMainKotlinMetadata   # Apple code, compiled on any host
./gradlew :crypto:iosSimulatorArm64Test :crypto:macosArm64Test   # macOS only
```

## Versioning

Releases follow [semantic versioning](https://semver.org/): a breaking change to the public API
bumps the major version. Each release is tagged `v<version>` and listed on the
[releases page](https://github.com/vitorpamplona/crypto-kmp/releases).

## License

MIT, see [LICENSE](LICENSE). The constant-time AES (`aes/AesBitsliced.kt`) and GHASH
(`aes/Ghash.kt`) are ports of BearSSL's `aes_ct64` and `ghash_ctmul64`, Copyright (c) 2016 Thomas
Pornin, also MIT.
