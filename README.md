# crypto-kmp

Cryptographic primitives for Kotlin Multiplatform: JVM, Android, iOS, macOS and Linux. The
library depends on nothing but the Kotlin stdlib. It uses the platform's implementation where
one is fast and available (JCA on the JVM and Android, CommonCrypto on Apple) and pure Kotlin
everywhere else. The AES and GHASH cores are constant-time.

It is the crypto layer of [Quartz](https://github.com/vitorpamplona/quartz) (the Nostr library
behind Amethyst), [mls-kmp](https://github.com/vitorpamplona/mls-kmp) (the MLS engine under
[marmot-kmp](https://github.com/vitorpamplona/marmot-kmp) and
[cordn-kmp](https://github.com/vitorpamplona/cordn-kmp)) and
[quic-kmp](https://github.com/vitorpamplona/quic-kmp).

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
| `DigestInstance` (SHA-1, SHA-256, SHA-512, RIPEMD-160), streaming | `digest` | JCA (SHA), Kotlin (RIPEMD-160) | CommonCrypto (SHA), Kotlin (RIPEMD-160) | Kotlin |
| RIPEMD-160 (`RIPEMD160Digest`), Keccak (`KeccakDigest`) | `digest` | Kotlin | Kotlin | Kotlin |
| HMAC-SHA1 / HMAC-SHA256 / HMAC-SHA512 (`MacInstance`) | `mac` | JCA | CommonCrypto | Kotlin |
| HKDF (RFC 5869) and TLS 1.3 `expandLabel` | `kdf` | on `MacInstance` | on `MacInstance` | on `MacInstance` |
| AES-GCM (any nonce length, 128-bit tag) | `aes` | JCA | Kotlin, constant-time | Kotlin, constant-time |
| AES-CBC with PKCS#7 | `aes` | JCA | CommonCrypto | Kotlin, constant-time |
| ChaCha20, Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305 | `chacha` | Kotlin | Kotlin | Kotlin |
| X25519, Ed25519 | `curve25519` | Kotlin (Ed25519 hashes with JCA) | Kotlin | Kotlin |
| Secure random (`RandomInstance`) | `random` | `java.security.SecureRandom` | `SecRandomCopyBytes` | `getrandom(2)` |

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
Each primitive also has negative tests (tampered tags, bad padding, wrong sizes, low-order and
non-canonical points), and JVM tests compare AES, ChaCha20-Poly1305, X25519, Ed25519, SHA and
HMAC with JCA on random inputs.

## Developer Setup

```bash
./gradlew installGitHook            # pre-commit (spotless) and pre-push (tests) hooks
./gradlew spotlessApply
./gradlew :crypto:jvmTest :crypto:testAndroidHostTest :crypto:linuxX64Test
./gradlew :crypto:compileAppleMainKotlinMetadata   # Apple code, compiled on any host
./gradlew :crypto:checkKotlinAbi    # public API matches crypto/api; updateKotlinAbi to accept a change
./gradlew :crypto:iosSimulatorArm64Test :crypto:macosArm64Test   # macOS only
```

## Versioning

Releases follow [semantic versioning](https://semver.org/): a breaking change to the public API
bumps the major version. Each release is tagged `v<version>` and listed on the
[releases page](https://github.com/vitorpamplona/crypto-kmp/releases). The public API is recorded
in `crypto/api/` and checked by `checkKotlinAbi`, so a change to it shows up in review.

### Migrating from 1.x

2.0 makes every platform behave the same and closes the gaps a review found. What callers see:

- **Errors**: AES-GCM, AES-CBC, ChaCha20-Poly1305 and XChaCha20-Poly1305 throw
  `IllegalArgumentException` on a bad tag or padding, on every platform. Code that caught
  `AEADBadTagException`, `BadPaddingException` or `IllegalStateException` catches
  `IllegalArgumentException`, or uses `decryptOrNull`. Wrong key, nonce and IV sizes throw where
  they used to be truncated or fail later.
- **AES**: a second `encrypt` on one `AESGCM` throws. `AESGCM.NAME` and `AESCBC.NAME` are now
  `AES_GCM_NAME` and `AES_CBC_NAME`. `AESCBC.decrypt` of an empty array throws on the JVM too.
  `AESGCM.decryptOrNull(bytes, aad)` is new.
- **ChaCha**: `ChaCha20` is an `object` (`ChaCha20.encrypt(…)`). A block counter that would wrap
  past 2^32 throws. Both AEADs gained `decryptOrNull`.
- **Curve25519**: `Ed25519.verify` returns `false` (instead of throwing) for a wrong-length key,
  and rejects small-order and non-canonical keys and `R`. `Ed25519.sign` and
  `publicFromPrivate` derive the public key from the seed.
- **Hashes and MACs**: `Hkdf(algorithm, hashLen)` is `Hkdf(algorithm)`, with `hashLen` derived.
  `DigestInstance` and `MacInstance` accept the same names everywhere (RIPEMD-160 now works on
  the JVM, SHA-512 and HMAC-SHA1 off it). `KeccakDigest()` is Keccak-256 (it was 288-bit), and
  its internal state is private. `Memoable`, `ExtendedDigest` and `Pack` are gone.
- **Random**: on the JVM and Android, `SecureRandom` wraps `java.security.SecureRandom` instead
  of being it. `RandomInstance.randomizer` is private.
- **Visibility**: `threadLocalDigest`, `FixedKey`, `DigestInstance.digest`, `MacInstance.mac` and
  `Sha256Hasher.digest` are no longer public.

## License

MIT, see [LICENSE](LICENSE). Ported code keeps its attribution in the source:

- The constant-time AES (`aes/AesBitsliced.kt`) and GHASH (`aes/Ghash.kt`) are ports of
  BearSSL's `aes_ct64` and `ghash_ctmul64`, Copyright (c) 2016 Thomas Pornin, MIT.
- `GeneralDigest`, `RIPEMD160Digest`, `KeccakDigest` and `Digest` are ports of Bouncy Castle's,
  Copyright (c) 2000-2024 The Legion of the Bouncy Castle Inc., MIT.
- Poly1305 follows Andrew Moon's poly1305-donna-32 (public domain / MIT).
- The Curve25519 field and point arithmetic follow TweetNaCl and ref10 (both public domain).
