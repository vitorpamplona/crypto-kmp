# crypto-kmp

The cryptographic primitives behind [Quartz](https://github.com/vitorpamplona/quartz),
[mls-kmp](https://github.com/vitorpamplona/mls-kmp) (and through it marmot-kmp and cordn-kmp) and
[quic-kmp](https://github.com/vitorpamplona/quic-kmp), as a small Kotlin Multiplatform library with
no dependencies beyond the Kotlin stdlib. Published to Maven Central as
`com.vitorpamplona.crypto:crypto`. The code started in Quartz and moved here so a QUIC client (or
anything else) can hash, MAC and encrypt without pulling in a Nostr library.

## Layout

- `crypto/` — the library, in `com.vitorpamplona.crypto.*`: `sha2` (SHA-1/256/512, `sha256()`,
  `Sha256Midstate`, the JVM `Sha256Pool`), `digest` (`DigestInstance`, RIPEMD-160, Keccak), `mac`
  (`MacInstance`, HMAC), `kdf` (`Hkdf`), `aes` (`AESGCM`, `AESCBC`), `chacha` (ChaCha20,
  Poly1305, ChaCha20-Poly1305, XChaCha20-Poly1305), `curve25519` (X25519, Ed25519), `random`
  (`RandomInstance`, `SecureRandom`), plus `SymmetricCipher` and `equalsConstantTime` at the root.
- Source sets: `jvmAndroid` (JCA, shared by JVM and Android); `nativeMain` (the Kotlin
  implementations every native target uses) above `appleMain` (CommonCrypto where it has the
  algorithm) and `linuxMain`.

## Rules

- **No dependencies** beyond the Kotlin stdlib (and `kotlin-test` for tests). That is the point
  of the library: depending on it never brings anything else onto a classpath. A new dependency
  needs its license checked against its actual `LICENSE` file first, and a very good reason.
- **No Nostr, no app concerns.** No protocol names, no NIP references, no logging: a primitive
  can't tell an expected failure from an alarming one, so `decryptOrNull` returns `null` and the
  caller decides whether to log.
- **Constant time** for anything that touches secrets: no table lookups or branches indexed by
  key or data (see `AesBitsliced`, `Ghash`), and compare MACs and tags with `equalsConstantTime`.
- **Prefer the platform's implementation** where it is fast and present (JCA, CommonCrypto), and
  keep a pure-Kotlin one for the targets without it. Every primitive gets known-answer vectors in
  `commonTest`, so each platform is held to the same bytes, plus a JVM test against JCA where JCA
  has the algorithm.
- `commonMain` and `commonTest` stay free of JVM-only APIs: the Linux and Apple targets compile
  them as common code. For `@Volatile` import `kotlin.concurrent.Volatile`; in tests use
  `assertTrue`, not `assert`.
- Apple code compiles on Linux as metadata (`:crypto:compileAppleMainKotlinMetadata`) but runs
  only on macOS: CI's `test-apple` job is where the CommonCrypto actuals execute.
- Code ported from elsewhere keeps its attribution (the AES and GHASH cores are BearSSL's, MIT).
- JVM target is 17: Quartz targets 17, and a dependency can't need a newer JVM than its user.
- Before pushing: `./gradlew spotlessApply`, then
  `./gradlew :crypto:checkKotlinAbi :crypto:jvmTest :crypto:testAndroidHostTest :crypto:linuxX64Test :crypto:compileAppleMainKotlinMetadata`
  (the pre-push hook runs these; `./gradlew installGitHook` installs it).
- **Explicit API mode** is on: every public declaration says `public`, and `crypto/api/` records
  the public ABI. A deliberate API change runs `./gradlew :crypto:updateKotlinAbi` and commits the
  new dump; anything that should not be API is `internal`.
- **Same behaviour on every platform** behind an `expect`: the same inputs accepted, the same
  exceptions. Wrong sizes and failed authentication throw `IllegalArgumentException` (wrap JCA's
  `GeneralSecurityException`), and `decryptOrNull` returns `null` for exactly the latter. Wipe
  secret temporaries (`fill(0)`) once done with them.
- Releases follow semantic versioning: a breaking change to the public API bumps the major
  version. Quartz, mls-kmp, quic-kmp, marmot-kmp, cordn-kmp and Amethyst pin a version and are
built to agree on it, so a breaking change needs matching releases there.
- Commits: conventional commits (`feat:`, `fix:`, …). Never `--no-verify`.

## Releasing

Bump `VERSION_NAME` in `gradle.properties`, then push a `v<version>` tag. The
`create-release.yml` workflow runs the Apple tests on macOS, then tests, publishes to Maven
Central and opens the GitHub release. It needs the same signing secrets as quic-kmp
(`SONATYPE_USERNAME`, `SONATYPE_PASSWORD`, `SIGNING_PRIVATE_KEY`, `SIGNING_PASSWORD`).
