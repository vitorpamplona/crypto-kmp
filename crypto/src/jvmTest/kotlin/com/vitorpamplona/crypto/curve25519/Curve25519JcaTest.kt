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
package com.vitorpamplona.crypto.curve25519

import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.EdECPrivateKey
import java.security.interfaces.EdECPublicKey
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import java.security.spec.EdECPoint
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The pure-Kotlin Ed25519 and X25519 every platform runs, compared with JDK 17's
 * SunEC on random keys and messages: public keys, signatures (Ed25519 is
 * deterministic, so they must match byte for byte), verify results on genuine
 * and corrupted signatures, and shared secrets.
 */
class Curve25519JcaTest {
    private val random = Random(25519)

    /** 32 little-endian bytes of a non-negative [value] below 2^256. */
    private fun littleEndian(value: BigInteger): ByteArray {
        val bigEndian = value.toByteArray()
        val out = ByteArray(32)
        for (i in 0 until minOf(32, bigEndian.size)) out[i] = bigEndian[bigEndian.size - 1 - i]
        return out
    }

    private fun fromLittleEndian(bytes: ByteArray): BigInteger = BigInteger(1, bytes.reversedArray())

    /** RFC 8032 encoding of a JCA Ed25519 public key: y little-endian, x's parity in the top bit. */
    private fun encode(key: EdECPublicKey): ByteArray {
        val out = littleEndian(key.point.y)
        if (key.point.isXOdd) out[31] = (out[31].toInt() or 0x80).toByte()
        return out
    }

    private fun jcaEd25519PublicKey(encoded: ByteArray): PublicKey {
        val y = encoded.copyOf()
        val xOdd = (y[31].toInt() and 0x80) != 0
        y[31] = (y[31].toInt() and 0x7f).toByte()
        val spec = EdECPublicKeySpec(NamedParameterSpec.ED25519, EdECPoint(xOdd, fromLittleEndian(y)))
        return KeyFactory.getInstance("Ed25519").generatePublic(spec)
    }

    /** JCA's verdict, with the exceptions SunEC throws for malformed input counted as a rejection. */
    private fun jcaVerify(
        publicKey: PublicKey,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean =
        try {
            Signature.getInstance("Ed25519").run {
                initVerify(publicKey)
                update(message)
                verify(signature)
            }
        } catch (e: GeneralSecurityException) {
            false
        }

    @Test
    fun ed25519MatchesJca() {
        val generator = KeyPairGenerator.getInstance("Ed25519")
        repeat(200) { i ->
            val pair = generator.generateKeyPair()
            val seed = (pair.private as EdECPrivateKey).bytes.get()
            val jcaPublic = encode(pair.public as EdECPublicKey)

            val ours = Ed25519.keyPairFromSeed(seed)
            assertContentEquals(jcaPublic, ours.publicKey, "public key $i")

            val message = random.nextBytes(random.nextInt(0, 300))
            val jcaSignature =
                Signature.getInstance("Ed25519").run {
                    initSign(pair.private)
                    update(message)
                    sign()
                }
            val ourSignature = Ed25519.sign(message, ours.privateKey)
            assertContentEquals(jcaSignature, ourSignature, "signature $i")

            val jcaKey = jcaEd25519PublicKey(ours.publicKey)
            assertTrue(jcaVerify(jcaKey, message, ourSignature), "JCA verifies ours $i")
            assertTrue(Ed25519.verify(message, jcaSignature, jcaPublic), "we verify JCA's $i")

            // One flipped bit in the signature or the message: both must say no.
            val bit = random.nextInt(512)
            val badSignature = ourSignature.copyOf()
            badSignature[bit shr 3] = (badSignature[bit shr 3].toInt() xor (1 shl (bit and 7))).toByte()
            assertEquals(jcaVerify(jcaKey, message, badSignature), Ed25519.verify(message, badSignature, ours.publicKey), "bit $bit, $i")
            if (message.isNotEmpty()) {
                val badMessage = message.copyOf()
                val index = random.nextInt(badMessage.size)
                badMessage[index] = (badMessage[index].toInt() xor 1).toByte()
                assertEquals(jcaVerify(jcaKey, badMessage, ourSignature), Ed25519.verify(badMessage, ourSignature, ours.publicKey), "message $i")
            }
        }
    }

    @Test
    fun x25519PublicKeysMatchJca() {
        val generator = KeyPairGenerator.getInstance("X25519")
        repeat(200) { i ->
            val pair = generator.generateKeyPair()
            val scalar = (pair.private as XECPrivateKey).scalar.get()
            assertContentEquals(littleEndian((pair.public as XECPublicKey).u), X25519.publicFromPrivate(scalar), "pair $i")
        }
    }

    private fun jcaX25519(
        scalar: ByteArray,
        u: ByteArray,
    ): ByteArray {
        val factory = KeyFactory.getInstance("XDH")
        val private: PrivateKey = factory.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, scalar))
        val masked = u.copyOf().also { it[31] = (it[31].toInt() and 0x7f).toByte() }
        val public = factory.generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, fromLittleEndian(masked)))
        return KeyAgreement.getInstance("XDH").run {
            init(private)
            doPhase(public, true)
            generateSecret()
        }
    }

    @Test
    fun x25519SharedSecretsMatchJca() {
        repeat(200) { i ->
            val alice = random.nextBytes(32)
            val bob = random.nextBytes(32)
            val bobPublic = X25519.publicFromPrivate(bob)
            assertContentEquals(jcaX25519(alice, bobPublic), X25519.dh(alice, bobPublic), "pair $i")
            assertContentEquals(X25519.dh(bob, X25519.publicFromPrivate(alice)), X25519.dh(alice, bobPublic), "agreement $i")

            // Any u, on the curve or on its twist, with the top bit cleared as JCA wants it.
            val u = random.nextBytes(32).also { it[31] = (it[31].toInt() and 0x7f).toByte() }
            assertContentEquals(jcaX25519(alice, u), X25519.dh(alice, u), "random u $i")
        }
    }
}
