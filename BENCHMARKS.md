# Benchmarks

How crypto-kmp compares with the libraries a JVM or JavaScript developer would otherwise use.
The `:benchmark` module runs them (it is not published, so none of these libraries reach the
library's users):

```bash
./gradlew :benchmark:jvmBenchmark      # JMH: crypto-kmp, JCA, Bouncy Castle
./gradlew :benchmark:jsBenchmark       # benchmark.js on Node: crypto-kmp, noble, TweetNaCl, node:crypto
./gradlew :benchmark:wasmJsBenchmark   # crypto-kmp on Kotlin/Wasm
./gradlew :benchmark:jvmSmokeBenchmark # one short iteration of each, to check they run
```

Every library does the same work per call: a fresh nonce for every AEAD message, keys parsed
once beforehand, the 1 KiB or 16 KiB message from `Inputs`. The module's tests
(`./gradlew :benchmark:jvmTest :benchmark:jsNodeTest`, run in CI) check that each library's
benchmark returns the bytes crypto-kmp's does.

## Results

Average microseconds per operation, lower is faster: 3 warm-up and 5 measured one-second
iterations. Run on 2026-10-25 on a shared 4-vCPU Intel Xeon at 2.1 GHz (a cloud VM, so allow
10-20% noise; JMH's error bars are in the raw output), OpenJDK 21.0.12 and Node.js 26.2.

### JVM

In parentheses: the time over crypto-kmp's, so above 1× is slower than crypto-kmp.

| Operation | crypto-kmp | JCA (JDK 21) | Bouncy Castle 1.83 |
|---|---:|---:|---:|
| SHA-256, 1 KiB | 0.74 | 0.78 (1.1×) | 6.62 (8.9×) |
| SHA-512, 1 KiB | 2.20 | 2.01 (0.91×) | 4.55 (2.1×) |
| HMAC-SHA256, 1 KiB | 1.22 | 1.20 (0.98×) | 8.23 (6.7×) |
| HKDF-SHA256, 32 B out | 1.11 | — | 3.80 (3.4×) |
| AES-256-GCM encrypt, 1 KiB | 2.12 | 2.28 (1.1×) | 18.5 (8.7×) |
| AES-256-GCM encrypt, 16 KiB | 7.73 | 6.02 (0.78×) | 168 (21.8×) |
| ChaCha20-Poly1305 encrypt, 1 KiB | 3.86 | 2.19 (0.57×) | 8.12 (2.1×) |
| ChaCha20-Poly1305 encrypt, 16 KiB | 59.7 | 11.5 (0.19×) | 115 (1.9×) |
| XChaCha20-Poly1305 encrypt, 1 KiB | 4.05 | — | — |
| X25519 public key | 39.5 | — | 30.0 (0.76×) |
| X25519 shared secret | 110 | 142 (1.3×) | 77.2 (0.70×) |
| Ed25519 sign, 1 KiB | 87.9 | 690 (7.8×) | 41.9 (0.48×) |
| Ed25519 verify, 1 KiB | 135 | 663 (4.9×) | 94.5 (0.70×) |

### JavaScript and Wasm (Node.js)

In parentheses: the time over noble's, the reference pure-JavaScript implementation, so above 1×
is slower than noble. node:crypto is OpenSSL in C and exists only on servers; a browser has
noble-style JavaScript, Wasm, or Web Crypto's async-only API.

| Operation | crypto-kmp, Kotlin/JS | crypto-kmp, Kotlin/Wasm | noble 2.4 | TweetNaCl 1.0.3 | node:crypto |
|---|---:|---:|---:|---:|---:|
| SHA-256, 1 KiB | 15.4 (2.2×) | 10.5 (1.5×) | 7.07 | — | 2.48 (0.4×) |
| SHA-512, 1 KiB | 256 (17×) | 9.80 (0.7×) | 14.9 | 22.9 (1.5×) | 3.73 (0.2×) |
| HMAC-SHA256, 1 KiB | 31.5 (2.8×) | 15.1 (1.4×) | 11.1 | — | 2.84 (0.3×) |
| HKDF-SHA256, 32 B out | 61.8 (5.8×) | 9.36 (0.9×) | 10.7 | — | 7.34 (0.7×) |
| AES-256-GCM encrypt, 1 KiB | 2077 (35×) | 33.8 (0.6×) | 58.8 | — | 7.58 (0.1×) |
| AES-256-GCM encrypt, 16 KiB | 33248 (78×) | 458 (1.1×) | 428 | — | 13.1 (0.03×) |
| ChaCha20-Poly1305 encrypt, 1 KiB | 242 (9.4×) | 7.67 (0.3×) | 25.8 | — | 9.76 (0.4×) |
| ChaCha20-Poly1305 encrypt, 16 KiB | 3593 (30×) | 97.7 (0.8×) | 120 | — | 18.4 (0.2×) |
| XChaCha20-Poly1305 encrypt, 1 KiB | 247 (8.9×) | 8.56 (0.3×) | 27.9 | — | — |
| X25519 public key | 8667 (26×) | 67.3 (0.2×) | 340 | 674 (2.0×) | — |
| X25519 shared secret | 25099 (21×) | 164 (0.1×) | 1186 | 666 (0.6×) | 39.0 (0.03×) |
| Ed25519 sign, 1 KiB | 17742 (30×) | 188 (0.3×) | 597 | 14969 (25×) | 40.0 (0.07×) |
| Ed25519 verify, 1 KiB | 32802 (26×) | 192 (0.2×) | 1268 | 30764 (24×) | 112 (0.09×) |

## What the numbers say

- **JVM, hashes, HMAC and AES-GCM: as fast as JCA**, because they are JCA (AES-NI, CLMUL and
  SHA intrinsics), and 2-22× faster than Bouncy Castle's table-based pure Java.
- **JVM, ChaCha20-Poly1305: now JCA's wherever JCA is faster.** In the run above the Kotlin
  code was 2× faster than Bouncy Castle but 1.8× (1 KiB) to 5× (16 KiB) slower than JCA, whose
  ChaCha20 and Poly1305 HotSpot compiles to vector instructions. With JCA, crypto-kmp measured
  2.6 µs (1 KiB) and 11.9 µs (16 KiB), level with JCA. Without those intrinsics (Java 17, or a
  CPU without them), SunJCE is pure Java and slower than the Kotlin code: 6.9 and 86 µs with
  both turned off, against Kotlin's 3.9 and 60. So the library only takes SunJCE when both are on.
- **JVM, Curve25519: 1.3× (X25519 public key) to 2.1× (Ed25519 sign) behind Bouncy Castle**, and well
  ahead of JCA's SunEC (4.9-7.8× on Ed25519).
- **Kotlin/Wasm is the fast web target**: faster than noble on everything but SHA-256, HMAC
  and 16 KiB AES-GCM (all within 1.5×), and 3-7× faster on the curves. The benchmark keeps the
  data in Wasm memory; a web app passing bytes in from JavaScript also pays a copy.
- **Kotlin/JS is 2-78× slower than noble.** Kotlin/JS has no 64-bit integers, and every
  primitive here leans on `Long`: SHA-512, the bitsliced AES and GHASH, Poly1305's limb
  products and the Curve25519 field. Only SHA-256, which is all 32-bit, stays within 2.2×.

## Where to improve, by payoff

1. **Kotlin/JS: 32-bit cores behind an internal `expect`**, each held to the same vectors
   (KATs and Wycheproof) as the current ones. In payoff order:
   - AES-GCM (35-78×): BearSSL's 32-bit `aes_ct` and `ghash_ctmul32`, siblings of the
     `aes_ct64` and `ghash_ctmul64` ported now.
   - Curve25519 (21-30×): a field over `Double` limbs, as TweetNaCl-js does (16 limbs of 16
     bits, products exact in a double's 53 bits). JS engines run those as native floats.
   - Poly1305 (most of ChaCha20-Poly1305's 9-30×): 13- or 16-bit limbs whose products fit an
     `Int` and `Math.imul`, as poly1305-donna-16 and noble do.
   - SHA-512 (17×): rounds on (hi, lo) `Int` pairs, as noble does.
2. ~~JVM ChaCha20-Poly1305: use JCA where it is faster.~~ Done: Android's BoringSSL (API 28+),
   a bundled Conscrypt, or SunJCE with both HotSpot intrinsics on; the Kotlin code everywhere
   else, including Java 17. Up to 5× at 16 KiB.
3. **JVM Curve25519: close the 1.3-2.1× gap to Bouncy Castle.** Ed25519 signing is the widest:
   Bouncy Castle's fixed-base multiplication is a precomputed comb, ours a ref10-style
   table; profile before choosing.
4. **Web guidance:** prefer `wasmJs` for anything on a hot path, which the README now says.
