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
package com.vitorpamplona.crypto.mac

import com.vitorpamplona.crypto.sha2.Sha256Digest
import com.vitorpamplona.crypto.sha2.Sha384Digest
import com.vitorpamplona.crypto.sha2.Sha512Digest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** RFC 4231 vectors for the pure-Kotlin HMAC behind the native [MacInstance]. */
class HmacTest {
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private class Case(
        val key: ByteArray,
        val message: ByteArray,
        val sha256: String,
        val sha512: String,
    )

    private val cases =
        listOf(
            // Test case 1
            Case(
                ByteArray(20) { 0x0b },
                "Hi There".encodeToByteArray(),
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
                    "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
            // Test case 2: a key shorter than the output
            Case(
                "Jefe".encodeToByteArray(),
                "what do ya want for nothing?".encodeToByteArray(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
                    "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ),
            // Test case 6: a key longer than the block, hashed first
            Case(
                ByteArray(131) { 0xaa.toByte() },
                "Test Using Larger Than Block-Size Key - Hash Key First".encodeToByteArray(),
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352" +
                    "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            ),
        )

    /** RFC 4231's seven HMAC-SHA-384 cases; case 5 checks only the first 128 bits, as the RFC does. */
    private val sha384Cases =
        listOf(
            Triple(ByteArray(20) { 0x0b }, "Hi There".encodeToByteArray(), "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
            Triple("Jefe".encodeToByteArray(), "what do ya want for nothing?".encodeToByteArray(), "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"),
            Triple(ByteArray(20) { 0xaa.toByte() }, ByteArray(50) { 0xdd.toByte() }, "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27"),
            Triple(ByteArray(25) { (it + 1).toByte() }, ByteArray(50) { 0xcd.toByte() }, "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb"),
            Triple(ByteArray(20) { 0x0c }, "Test With Truncation".encodeToByteArray(), "3abf34c3503b2a23a46efc619baef897"),
            Triple(ByteArray(131) { 0xaa.toByte() }, "Test Using Larger Than Block-Size Key - Hash Key First".encodeToByteArray(), "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"),
            Triple(
                ByteArray(131) { 0xaa.toByte() },
                (
                    "This is a test using a larger than block-size key and a larger than block-size data. " +
                        "The key needs to be hashed before being used by the HMAC algorithm."
                ).encodeToByteArray(),
                "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            ),
        )

    @Test
    fun rfc4231Sha384EveryCase() {
        for ((i, case) in sha384Cases.withIndex()) {
            val (key, message, expected) = case
            val tag = Hmac(Sha384Digest(), key).apply { update(message) }.doFinal().hex()
            assertEquals(expected, tag.take(expected.length), "case ${i + 1}")
            assertEquals(96, tag.length)
        }
    }

    @Test
    fun rfc4231() {
        for (case in cases) {
            assertEquals(case.sha256, Hmac(Sha256Digest(), case.key).apply { update(case.message) }.doFinal().hex())
            assertEquals(case.sha512, Hmac(Sha512Digest(), case.key).apply { update(case.message) }.doFinal().hex())
        }
    }

    @Test
    fun staysKeyedAfterDoFinal() {
        val case = cases[1]
        val mac = Hmac(Sha256Digest(), case.key)
        repeat(3) {
            mac.update(case.message)
            assertEquals(case.sha256, mac.doFinal().hex())
        }
    }

    @Test
    fun shortOutputBufferLeavesTheMacUsable() {
        val case = cases[1]
        val mac = Hmac(Sha256Digest(), case.key)
        mac.update(case.message)
        assertFailsWith<IllegalArgumentException> { mac.doFinal(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { mac.doFinal(ByteArray(40), offset = 10) }
        // The message fed before the failed calls is still there.
        assertEquals(case.sha256, mac.doFinal().hex())
    }

    @Test
    fun rekeyMatchesAFreshInstance() {
        val mac = Hmac(Sha512Digest(), cases[0].key)
        mac.update("left over, dropped by rekey".encodeToByteArray())
        for (case in cases + cases) {
            mac.rekey(case.key)
            mac.update(case.message)
            assertEquals(case.sha512, mac.doFinal().hex())
        }
    }

    @Test
    fun doFinalWritesAtOffset() {
        val case = cases[0]
        val mac = Hmac(Sha256Digest(), case.key)
        mac.update(case.message)
        val out = ByteArray(40)
        mac.doFinal(out, 8)
        assertEquals(case.sha256, out.copyOfRange(8, 40).hex())
    }
}
