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
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.EdECPoint
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The JDK's own providers (SunJCE, SunEC), the baseline every JVM app already has. AES-GCM and
 * SHA there use the CPU's AES-NI, CLMUL and SHA instructions through HotSpot intrinsics.
 * Keys are parsed once in [setup]; each call does what a caller does per message.
 */
@State(Scope.Benchmark)
class Jca {
    private val nonces = NonceCounter()
    private val aesKey = SecretKeySpec(Inputs.aesKey, "AES")
    private val chachaKey = SecretKeySpec(Inputs.chachaKey, "ChaCha20")
    private val hmacKey = SecretKeySpec(Inputs.hmacKey, "HmacSHA256")
    private lateinit var x25519Private: PrivateKey
    private lateinit var x25519Public: PublicKey
    private lateinit var ed25519Private: PrivateKey
    private lateinit var ed25519Public: PublicKey
    private lateinit var ed25519Signature: ByteArray
    private lateinit var p256Private: PrivateKey
    private lateinit var p256Public: PublicKey

    @Setup
    fun setup() {
        val xdh = KeyFactory.getInstance("XDH")
        x25519Private = xdh.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, Inputs.x25519Private))
        // XECPublicKeySpec takes u as a big-endian integer; the encoding is little-endian.
        x25519Public = xdh.generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger(1, Inputs.x25519Public.reversedArray())))
        val ed = KeyFactory.getInstance("Ed25519")
        ed25519Private = ed.generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, Inputs.ed25519Seed))
        ed25519Signature =
            signature().run {
                initSign(ed25519Private)
                update(Inputs.message1k)
                sign()
            }
        val publicBytes =
            com.vitorpamplona.crypto.curve25519.Ed25519
                .keyPairFromSeed(Inputs.ed25519Seed)
                .publicKey
        ed25519Public = ed.generatePublic(EdECPublicKeySpec(NamedParameterSpec.ED25519, edPoint(publicBytes)))
        val p256 = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val ec = KeyFactory.getInstance("EC")
        p256Private = ec.generatePrivate(ECPrivateKeySpec(BigInteger(1, Inputs.p256Private), p256))
        val point = ECPoint(BigInteger(1, Inputs.p256Public.copyOfRange(1, 33)), BigInteger(1, Inputs.p256Public.copyOfRange(33, 65)))
        p256Public = ec.generatePublic(ECPublicKeySpec(point, p256))
    }

    @Benchmark
    fun sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(Inputs.message1k)

    @Benchmark
    fun sha512(): ByteArray = MessageDigest.getInstance("SHA-512").digest(Inputs.message1k)

    @Benchmark
    fun hmacSha256(): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(hmacKey)
        return mac.doFinal(Inputs.message1k)
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
    fun x25519SharedSecret(): ByteArray {
        val agreement = KeyAgreement.getInstance("XDH")
        agreement.init(x25519Private)
        agreement.doPhase(x25519Public, true)
        return agreement.generateSecret()
    }

    @Benchmark
    fun p256SharedSecret(): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(p256Private)
        agreement.doPhase(p256Public, true)
        return agreement.generateSecret()
    }

    @Benchmark
    fun ed25519Sign(): ByteArray {
        val signer = signature()
        signer.initSign(ed25519Private)
        signer.update(Inputs.message1k)
        return signer.sign()
    }

    @Benchmark
    fun ed25519Verify(): Boolean {
        val verifier = signature()
        verifier.initVerify(ed25519Public)
        verifier.update(Inputs.message1k)
        return verifier.verify(ed25519Signature)
    }

    private fun aesGcm(message: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, nonces.next()))
        cipher.updateAAD(Inputs.aad)
        return cipher.doFinal(message)
    }

    private fun chacha(message: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, chachaKey, IvParameterSpec(nonces.next()))
        cipher.updateAAD(Inputs.aad)
        return cipher.doFinal(message)
    }

    private fun signature() = Signature.getInstance("Ed25519")

    /** An RFC 8032 encoding as the JDK's point: y little-endian, x's parity in the top bit. */
    private fun edPoint(encoded: ByteArray): EdECPoint {
        val bytes = encoded.copyOf()
        val xOdd = (bytes[31].toInt() and 0x80) != 0
        bytes[31] = (bytes[31].toInt() and 0x7F).toByte()
        return EdECPoint(xOdd, BigInteger(1, bytes.reversedArray()))
    }
}
