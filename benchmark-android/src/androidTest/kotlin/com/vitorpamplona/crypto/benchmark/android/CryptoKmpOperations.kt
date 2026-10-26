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
package com.vitorpamplona.crypto.benchmark.android

import com.vitorpamplona.crypto.aes.AESGCM
import com.vitorpamplona.crypto.chacha.ChaCha20Poly1305
import com.vitorpamplona.crypto.chacha.XChaCha20Poly1305
import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.crypto.digest.DigestInstance
import com.vitorpamplona.crypto.ec.P256
import com.vitorpamplona.crypto.kdf.Hkdf
import com.vitorpamplona.crypto.mac.MacInstance
import com.vitorpamplona.crypto.sha2.sha256 as sha256Of

/** This library's public API, which on Android is JCA where it wins and Kotlin elsewhere. */
class CryptoKmpOperations : Operations {
    private val nonces = NonceCounter()
    private val ed25519 = Ed25519.keyPairFromSeed(Inputs.ed25519Seed)
    private val ed25519Signature = Ed25519.sign(Inputs.message1k, ed25519.privateKey)

    override fun sha256() = sha256Of(Inputs.message1k)

    override fun sha512() = DigestInstance("SHA-512").digest(Inputs.message1k)

    override fun hmacSha256(): ByteArray {
        val mac = MacInstance("HmacSHA256", Inputs.hmacKey)
        mac.update(Inputs.message1k)
        return mac.doFinal()
    }

    override fun hkdfSha256(): ByteArray {
        val hkdf = Hkdf()
        return hkdf.expand(hkdf.extract(Inputs.hmacKey, Inputs.aad), Inputs.aad, 32)
    }

    override fun aesGcm1k() = AESGCM(Inputs.aesKey, nonces.next()).encrypt(Inputs.message1k, Inputs.aad)

    override fun aesGcm16k() = AESGCM(Inputs.aesKey, nonces.next()).encrypt(Inputs.message16k, Inputs.aad)

    override fun chaChaPoly1k() = ChaCha20Poly1305.encrypt(Inputs.message1k, Inputs.aad, nonces.next(), Inputs.chachaKey)

    override fun chaChaPoly16k() = ChaCha20Poly1305.encrypt(Inputs.message16k, Inputs.aad, nonces.next(), Inputs.chachaKey)

    override fun xChaChaPoly1k() = XChaCha20Poly1305.encrypt(Inputs.message1k, Inputs.aad, Inputs.xNonce, Inputs.chachaKey)

    override fun x25519PublicKey() = X25519.publicFromPrivate(Inputs.x25519Private)

    override fun x25519SharedSecret() = X25519.dh(Inputs.x25519Private, Inputs.x25519Public)

    override fun p256PublicKey() = P256.publicFromPrivate(Inputs.p256Private)

    override fun p256SharedSecret() = P256.dh(Inputs.p256Private, Inputs.p256Public)

    override fun ed25519Sign() = Ed25519.sign(Inputs.message1k, ed25519.privateKey)

    override fun ed25519Verify() = Ed25519.verify(Inputs.message1k, ed25519Signature, ed25519.publicKey)
}
