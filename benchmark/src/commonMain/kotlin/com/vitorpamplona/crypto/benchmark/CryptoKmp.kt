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

import com.vitorpamplona.crypto.aes.AESGCM
import com.vitorpamplona.crypto.chacha.ChaCha20Poly1305
import com.vitorpamplona.crypto.chacha.XChaCha20Poly1305
import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.crypto.digest.DigestInstance
import com.vitorpamplona.crypto.kdf.Hkdf
import com.vitorpamplona.crypto.mac.MacInstance
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import com.vitorpamplona.crypto.sha2.sha256 as sha256Of

/**
 * This library, through its public API, on every platform the benchmarks run on. The other
 * libraries' classes use the same method names, so the reports line up by operation.
 */
@State(Scope.Benchmark)
class CryptoKmp {
    private val nonces = NonceCounter()
    private val xNonce = ByteArray(24) { it.toByte() }
    private lateinit var ed25519Private: ByteArray
    private lateinit var ed25519Public: ByteArray
    private lateinit var ed25519Signature: ByteArray

    @Setup
    fun setup() {
        val pair = Ed25519.keyPairFromSeed(Inputs.ed25519Seed)
        ed25519Private = pair.privateKey
        ed25519Public = pair.publicKey
        ed25519Signature = Ed25519.sign(Inputs.message1k, ed25519Private)
    }

    @Benchmark
    fun sha256(): ByteArray = sha256Of(Inputs.message1k)

    @Benchmark
    fun sha512(): ByteArray = DigestInstance("SHA-512").digest(Inputs.message1k)

    @Benchmark
    fun hmacSha256(): ByteArray {
        val mac = MacInstance("HmacSHA256", Inputs.hmacKey)
        mac.update(Inputs.message1k)
        return mac.doFinal()
    }

    @Benchmark
    fun hkdfSha256(): ByteArray {
        val hkdf = Hkdf()
        return hkdf.expand(hkdf.extract(Inputs.hmacKey, Inputs.aad), Inputs.aad, 32)
    }

    @Benchmark
    fun aesGcm1k(): ByteArray = AESGCM(Inputs.aesKey, nonces.next()).encrypt(Inputs.message1k, Inputs.aad)

    @Benchmark
    fun aesGcm16k(): ByteArray = AESGCM(Inputs.aesKey, nonces.next()).encrypt(Inputs.message16k, Inputs.aad)

    @Benchmark
    fun chaChaPoly1k(): ByteArray = ChaCha20Poly1305.encrypt(Inputs.message1k, Inputs.aad, nonces.next(), Inputs.chachaKey)

    @Benchmark
    fun chaChaPoly16k(): ByteArray = ChaCha20Poly1305.encrypt(Inputs.message16k, Inputs.aad, nonces.next(), Inputs.chachaKey)

    @Benchmark
    fun xChaChaPoly1k(): ByteArray = XChaCha20Poly1305.encrypt(Inputs.message1k, Inputs.aad, xNonce, Inputs.chachaKey)

    @Benchmark
    fun x25519PublicKey(): ByteArray = X25519.publicFromPrivate(Inputs.x25519Private)

    @Benchmark
    fun x25519SharedSecret(): ByteArray = X25519.dh(Inputs.x25519Private, Inputs.x25519Public)

    @Benchmark
    fun ed25519Sign(): ByteArray = Ed25519.sign(Inputs.message1k, ed25519Private)

    @Benchmark
    fun ed25519Verify(): Boolean = Ed25519.verify(Inputs.message1k, ed25519Signature, ed25519Public)
}
