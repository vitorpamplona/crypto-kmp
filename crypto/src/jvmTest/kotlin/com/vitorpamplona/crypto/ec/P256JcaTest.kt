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
package com.vitorpamplona.crypto.ec

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * The pure-Kotlin P-256 against JCA's (SunEC) on random keys: the public key of a JCA private
 * key, ECDH both ways, and the field arithmetic underneath against BigInteger.
 */
class P256JcaTest {
    private val random = Random(5903)
    private val p = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)

    private fun BigInteger.to32(): ByteArray {
        val bytes = toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - bytes.size) + bytes
    }

    private fun encode(w: ECPoint): ByteArray = byteArrayOf(4) + w.affineX.to32() + w.affineY.to32()

    @Test
    fun matchesJcaOnRandomKeys() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val factory = KeyFactory.getInstance("EC")
        repeat(100) { round ->
            val a = generator.generateKeyPair()
            val b = generator.generateKeyPair()
            val aPrivate = (a.private as ECPrivateKey).s.to32()
            val bPublic = encode((b.public as ECPublicKey).w)
            assertContentEquals(encode((a.public as ECPublicKey).w), P256.publicFromPrivate(aPrivate), "round $round")

            val jca =
                KeyAgreement.getInstance("ECDH").run {
                    init(a.private)
                    doPhase(b.public, true)
                    generateSecret()
                }
            assertContentEquals(jca, P256.dh(aPrivate, bPublic), "round $round")

            // And the other way: this library's key pair, agreed with by JCA.
            val ours = P256.generateKeyPair()
            val ourPublic =
                factory.generatePublic(
                    ECPublicKeySpec(
                        ECPoint(BigInteger(1, ours.publicKey.copyOfRange(1, 33)), BigInteger(1, ours.publicKey.copyOfRange(33, 65))),
                        (b.public as ECPublicKey).params,
                    ),
                )
            val jcaSide =
                KeyAgreement.getInstance("ECDH").run {
                    init(b.private)
                    doPhase(ourPublic, true)
                    generateSecret()
                }
            assertContentEquals(jcaSide, P256.dh(ours.privateKey, bPublic), "round $round")
        }
    }

    @Test
    fun fieldArithmeticMatchesBigInteger() {
        val r = BigInteger.ONE.shiftLeft(256).mod(p)
        val rInverse = r.modInverse(p)
        repeat(2000) {
            val a = BigInteger(256, java.util.Random(random.nextLong())).mod(p)
            val b = if (it % 10 == 0) p.subtract(BigInteger.ONE) else BigInteger(256, java.util.Random(random.nextLong())).mod(p)
            val fa = P256Field.fromBytes(a.to32(), 0)
            val fb = P256Field.fromBytes(b.to32(), 0)
            val out = P256Field.zero()

            P256Field.add(out, fa, fb)
            assertEquals(a.add(b).mod(p), value(out))
            P256Field.sub(out, fa, fb)
            assertEquals(a.subtract(b).mod(p), value(out))
            // mul is Montgomery's: a·b·R^-1.
            P256Field.mul(out, fa, fb)
            assertEquals(a.multiply(b).multiply(rInverse).mod(p), value(out))

            val ma = P256Field.zero().also { P256Field.toMontgomery(it, fa) }
            assertEquals(a.multiply(r).mod(p), value(ma))
            P256Field.fromMontgomery(out, ma)
            assertEquals(a, value(out))
            if (a.signum() != 0) {
                P256Field.invert(out, ma)
                P256Field.fromMontgomery(out, out)
                assertEquals(a.modInverse(p), value(out))
            }
        }
    }

    private fun value(limbs: LongArray): BigInteger = BigInteger(1, ByteArray(32).also { P256Field.toBytes(limbs, it, 0) })
}
