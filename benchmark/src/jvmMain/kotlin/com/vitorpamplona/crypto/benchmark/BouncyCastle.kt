/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.crypto.benchmark

import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * Bouncy Castle's lightweight API: pure Java, like this library's Kotlin, and the usual
 * choice on Android and on JVMs whose providers lack an algorithm. Its AES is table-based
 * (fast, not constant-time); this library's Kotlin AES is bitsliced.
 */
@State(Scope.Benchmark)
class BouncyCastle {
    private val nonces = NonceCounter()
    private val aesKey = KeyParameter(Inputs.aesKey)
    private val chachaKey = KeyParameter(Inputs.chachaKey)
    private val ed25519Public = ByteArray(Ed25519.PUBLIC_KEY_SIZE)
    private lateinit var ed25519Signature: ByteArray

    @Setup
    fun setup() {
        Ed25519.generatePublicKey(Inputs.ed25519Seed, 0, ed25519Public, 0)
        ed25519Signature = ed25519Sign()
    }

    @Benchmark
    fun sha256(): ByteArray {
        val digest = SHA256Digest()
        digest.update(Inputs.message1k, 0, Inputs.message1k.size)
        return ByteArray(32).also { digest.doFinal(it, 0) }
    }

    @Benchmark
    fun sha512(): ByteArray {
        val digest = SHA512Digest()
        digest.update(Inputs.message1k, 0, Inputs.message1k.size)
        return ByteArray(64).also { digest.doFinal(it, 0) }
    }

    @Benchmark
    fun hmacSha256(): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(Inputs.hmacKey))
        mac.update(Inputs.message1k, 0, Inputs.message1k.size)
        return ByteArray(32).also { mac.doFinal(it, 0) }
    }

    @Benchmark
    fun hkdfSha256(): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(Inputs.hmacKey, Inputs.aad, Inputs.aad))
        return ByteArray(32).also { hkdf.generateBytes(it, 0, 32) }
    }

    @Benchmark
    fun aesGcm1k(): ByteArray = aesGcm(Inputs.message1k)

    @Benchmark
    fun aesGcm16k(): ByteArray = aesGcm(Inputs.message16k)

    @Benchmark
    fun chaChaPoly1k(): ByteArray = chacha(Inputs.message1k)

    @Benchmark
    fun chaChaPoly16k(): ByteArray = chacha(Inputs.message16k)

    @Benchmark
    fun x25519PublicKey(): ByteArray = ByteArray(X25519.POINT_SIZE).also { X25519.generatePublicKey(Inputs.x25519Private, 0, it, 0) }

    @Benchmark
    fun x25519SharedSecret(): ByteArray =
        ByteArray(X25519.POINT_SIZE).also {
            X25519.calculateAgreement(Inputs.x25519Private, 0, Inputs.x25519Public, 0, it, 0)
        }

    @Benchmark
    fun ed25519Sign(): ByteArray =
        ByteArray(Ed25519.SIGNATURE_SIZE).also {
            Ed25519.sign(Inputs.ed25519Seed, 0, ed25519Public, 0, Inputs.message1k, 0, Inputs.message1k.size, it, 0)
        }

    @Benchmark
    fun ed25519Verify(): Boolean = Ed25519.verify(ed25519Signature, 0, ed25519Public, 0, Inputs.message1k, 0, Inputs.message1k.size)

    private fun aesGcm(message: ByteArray): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        cipher.init(true, AEADParameters(aesKey, 128, nonces.next(), Inputs.aad))
        val out = ByteArray(cipher.getOutputSize(message.size))
        val n = cipher.processBytes(message, 0, message.size, out, 0)
        cipher.doFinal(out, n)
        return out
    }

    private fun chacha(message: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(chachaKey, 128, nonces.next(), Inputs.aad))
        val out = ByteArray(cipher.getOutputSize(message.size))
        val n = cipher.processBytes(message, 0, message.size, out, 0)
        cipher.doFinal(out, n)
        return out
    }
}
