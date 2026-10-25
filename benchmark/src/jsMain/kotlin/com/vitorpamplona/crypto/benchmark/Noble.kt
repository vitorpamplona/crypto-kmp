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

/** noble (@noble/hashes, ciphers, curves), the audited pure-JavaScript reference. */
@State(Scope.Benchmark)
class Noble {
    private val nonces = NonceCounter()
    private val message1k = uint8(Inputs.message1k)
    private val message16k = uint8(Inputs.message16k)
    private val aad = uint8(Inputs.aad)
    private val aesKey = uint8(Inputs.aesKey)
    private val chachaKey = uint8(Inputs.chachaKey)
    private val hmacKey = uint8(Inputs.hmacKey)
    private val xNonce = uint8(ByteArray(24) { it.toByte() })
    private val x25519Private = uint8(Inputs.x25519Private)
    private val x25519Public = uint8(Inputs.x25519Public)
    private val ed25519Seed = uint8(Inputs.ed25519Seed)
    private var ed25519Public: dynamic = null
    private var ed25519Signature: dynamic = null

    @Setup
    fun setup() {
        ed25519Public = NobleEd25519.ed25519.getPublicKey(ed25519Seed)
        ed25519Signature = NobleEd25519.ed25519.sign(message1k, ed25519Seed)
    }

    @Benchmark
    fun sha256(): Any = NobleSha2.sha256(message1k)

    @Benchmark
    fun sha512(): Any = NobleSha2.sha512(message1k)

    @Benchmark
    fun hmacSha256(): Any = NobleHmac.hmac(NobleSha2.asDynamic().sha256, hmacKey, message1k)

    @Benchmark
    fun hkdfSha256(): Any = NobleHkdf.hkdf(NobleSha2.asDynamic().sha256, hmacKey, aad, aad, 32)

    @Benchmark
    fun aesGcm1k(): Any = NobleAes.gcm(aesKey, uint8(nonces.next()), aad).encrypt(message1k)

    @Benchmark
    fun aesGcm16k(): Any = NobleAes.gcm(aesKey, uint8(nonces.next()), aad).encrypt(message16k)

    @Benchmark
    fun chaChaPoly1k(): Any = NobleChacha.chacha20poly1305(chachaKey, uint8(nonces.next()), aad).encrypt(message1k)

    @Benchmark
    fun chaChaPoly16k(): Any = NobleChacha.chacha20poly1305(chachaKey, uint8(nonces.next()), aad).encrypt(message16k)

    @Benchmark
    fun xChaChaPoly1k(): Any = NobleChacha.xchacha20poly1305(chachaKey, xNonce, aad).encrypt(message1k)

    @Benchmark
    fun x25519PublicKey(): Any = NobleEd25519.x25519.getPublicKey(x25519Private)

    @Benchmark
    fun x25519SharedSecret(): Any = NobleEd25519.x25519.getSharedSecret(x25519Private, x25519Public)

    @Benchmark
    fun ed25519Sign(): Any = NobleEd25519.ed25519.sign(message1k, ed25519Seed)

    @Benchmark
    fun ed25519Verify(): Boolean = NobleEd25519.ed25519.verify(ed25519Signature, message1k, ed25519Public) as Boolean
}
