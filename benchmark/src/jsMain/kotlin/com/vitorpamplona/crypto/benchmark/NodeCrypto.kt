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

/**
 * node:crypto, which is OpenSSL in C with the CPU's AES and SHA instructions: the ceiling for
 * JavaScript on a server, and absent from browsers, whose Web Crypto is async-only.
 */
@State(Scope.Benchmark)
class NodeCrypto {
    private val nonces = NonceCounter()
    private var x25519: dynamic = null
    private var ed25519Private: dynamic = null
    private var ed25519Public: dynamic = null
    private var ed25519Signature: dynamic = null

    @Setup
    fun setup() {
        // diffieHellman's argument: our private key and the peer's public one.
        x25519 = js("({})")
        x25519.privateKey = rawKey("X25519", Inputs.x25519Private)
        x25519.publicKey = nodeCrypto.createPublicKey(jwk("X25519", Inputs.x25519Public, null))
        ed25519Private = rawKey("Ed25519", Inputs.ed25519Seed)
        ed25519Public = nodeCrypto.createPublicKey(ed25519Private)
        ed25519Signature = nodeCrypto.sign(null, Inputs.message1k, ed25519Private)
    }

    @Benchmark
    fun sha256(): Any = nodeCrypto.createHash("sha256").update(Inputs.message1k).digest()

    @Benchmark
    fun sha512(): Any = nodeCrypto.createHash("sha512").update(Inputs.message1k).digest()

    @Benchmark
    fun hmacSha256(): Any = nodeCrypto.createHmac("sha256", Inputs.hmacKey).update(Inputs.message1k).digest()

    @Benchmark
    fun hkdfSha256(): Any = nodeCrypto.hkdfSync("sha256", Inputs.hmacKey, Inputs.aad, Inputs.aad, 32)

    @Benchmark
    fun aesGcm1k(): Any = aead("aes-256-gcm", Inputs.aesKey, Inputs.message1k)

    @Benchmark
    fun aesGcm16k(): Any = aead("aes-256-gcm", Inputs.aesKey, Inputs.message16k)

    @Benchmark
    fun chaChaPoly1k(): Any = aead("chacha20-poly1305", Inputs.chachaKey, Inputs.message1k)

    @Benchmark
    fun chaChaPoly16k(): Any = aead("chacha20-poly1305", Inputs.chachaKey, Inputs.message16k)

    @Benchmark
    fun x25519SharedSecret(): Any = nodeCrypto.diffieHellman(x25519)

    @Benchmark
    fun ed25519Sign(): Any = nodeCrypto.sign(null, Inputs.message1k, ed25519Private)

    @Benchmark
    fun ed25519Verify(): Boolean = nodeCrypto.verify(null, Inputs.message1k, ed25519Public, ed25519Signature) as Boolean

    private fun aead(
        algorithm: String,
        key: ByteArray,
        message: ByteArray,
    ): dynamic {
        val options: dynamic = js("({ authTagLength: 16 })")
        val cipher = nodeCrypto.createCipheriv(algorithm, key, nonces.next(), options)
        cipher.setAAD(Inputs.aad)
        val ciphertext = cipher.update(message)
        cipher.final()
        return arrayOf(ciphertext, cipher.getAuthTag())
    }

    /** A private KeyObject from its raw 32 bytes, through the JWK form node:crypto accepts. */
    private fun rawKey(
        curve: String,
        d: ByteArray,
    ): dynamic {
        val public =
            if (curve == "X25519") {
                com.vitorpamplona.crypto.curve25519.X25519
                    .publicFromPrivate(d)
            } else {
                com.vitorpamplona.crypto.curve25519.Ed25519
                    .keyPairFromSeed(d)
                    .publicKey
            }
        return nodeCrypto.createPrivateKey(jwk(curve, public, d))
    }

    private fun jwk(
        curve: String,
        x: ByteArray,
        d: ByteArray?,
    ): dynamic {
        val key: dynamic = js("({ kty: 'OKP' })")
        key.crv = curve
        key.x = base64Url(x)
        if (d != null) key.d = base64Url(d)
        val options: dynamic = js("({ format: 'jwk' })")
        options.key = key
        return options
    }

    private fun base64Url(bytes: ByteArray): String = js("Buffer").from(uint8(bytes)).toString("base64url") as String
}
