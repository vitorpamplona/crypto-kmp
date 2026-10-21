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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * [MacInstance] on every platform (JCA, CommonCrypto, pure Kotlin) with RFC 4231 and
 * RFC 2202 vectors: reuse after [MacInstance.doFinal], rekeying with [MacInstance.init],
 * empty keys, and the same errors everywhere for unknown names and short buffers. The
 * empty-key values were computed with Python's `hmac` module.
 */
class MacInstanceTest {
    private fun ByteArray.hex() = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private val key1 = ByteArray(20) { 0x0b }
    private val message1 = "Hi There".encodeToByteArray()
    private val key2 = "Jefe".encodeToByteArray()
    private val message2 = "what do ya want for nothing?".encodeToByteArray()

    private val sha256Case1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    private val sha256Case2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    private val sha512Case2 =
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
            "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"

    @Test
    fun reusesAndRekeys() {
        val mac = MacInstance("HmacSHA256", key1)
        assertEquals(32, mac.getMacLength())
        repeat(2) {
            mac.update(message1)
            assertEquals(sha256Case1, mac.doFinal().hex())
        }

        mac.init(key2, "HmacSHA256")
        message2.forEach { mac.update(it) }
        assertEquals(sha256Case2, mac.doFinal().hex())
    }

    @Test
    fun writesAtOffset() {
        val mac = MacInstance("HmacSHA512", key2)
        assertEquals(64, mac.getMacLength())
        mac.update(message2)
        val out = ByteArray(70)
        mac.doFinal(out, 3)
        assertEquals(sha512Case2, out.copyOfRange(3, 67).hex())
    }

    @Test
    fun hmacSha1Rfc2202() {
        val cases =
            listOf(
                Triple(ByteArray(20) { 0x0b }, "Hi There".encodeToByteArray(), "b617318655057264e28bc0b6fb378c8ef146be00"),
                Triple(key2, message2, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
                Triple(ByteArray(20) { 0xaa.toByte() }, ByteArray(50) { 0xdd.toByte() }, "125d7342b9ac11cd91a39af48aa17b4f63f175d3"),
                Triple(ByteArray(25) { (it + 1).toByte() }, ByteArray(50) { 0xcd.toByte() }, "4c9007f4026250c6bc8414f9bf50c86c2d7235da"),
                Triple(
                    ByteArray(80) { 0xaa.toByte() },
                    "Test Using Larger Than Block-Size Key - Hash Key First".encodeToByteArray(),
                    "aa4ae5e15272d00e95705637ce8a3b55ed402112",
                ),
                Triple(
                    ByteArray(80) { 0xaa.toByte() },
                    "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".encodeToByteArray(),
                    "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
                ),
            )
        for ((key, message, expected) in cases) {
            val mac = MacInstance("HmacSHA1", key)
            assertEquals(20, mac.getMacLength())
            mac.update(message)
            assertEquals(expected, mac.doFinal().hex())
        }
    }

    @Test
    fun emptyKey() {
        // CommonCrypto takes a null pointer for it, JCA a zero-length key; both pad to zeros.
        val message = "Hi There".encodeToByteArray()
        val expected =
            mapOf(
                "HmacSHA1" to "69536cc84eee5fe51c5b051aff8485f5c9ef0b58",
                "HmacSHA256" to "e48411262715c8370cd5e7bf8e82bef53bd53712d007f3429351843b77c7bb9b",
                "HmacSHA512" to
                    "f7688a104326d36c1940f6d28d746c0661d383e0d14fe8a04649444777610f5d" +
                    "d9565a36846ab9e9e734cf380d3a070d8ef021b5f3a50c481710a464968e3419",
            )
        for ((algorithm, mac) in expected) {
            val instance = MacInstance(algorithm, ByteArray(0))
            repeat(2) {
                instance.update(message)
                assertEquals(mac, instance.doFinal().hex(), algorithm)
            }
            // Re-armed with the empty key after a non-empty one.
            instance.init(key1, algorithm)
            instance.init(ByteArray(0), algorithm)
            instance.update(message)
            assertEquals(mac, instance.doFinal().hex(), algorithm)
        }
        assertEquals(
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
            MacInstance("HmacSHA256", ByteArray(0)).doFinal().hex(),
        )
    }

    @Test
    fun initSwitchesAlgorithm() {
        val mac = MacInstance("HmacSHA256", key1)
        mac.init(key2, "HmacSHA512")
        assertEquals(64, mac.getMacLength())
        mac.update(message2)
        assertEquals(sha512Case2, mac.doFinal().hex())

        mac.init(key2, "HmacSHA256")
        assertEquals(32, mac.getMacLength())
        mac.update(message2)
        assertEquals(sha256Case2, mac.doFinal().hex())
    }

    @Test
    fun namesMatchIgnoringCase() {
        for (name in listOf("HmacSHA256", "hmacsha256", "HMACSHA256")) {
            val mac = MacInstance(name, key2)
            mac.update(message2)
            assertEquals(sha256Case2, mac.doFinal().hex(), name)
        }
    }

    @Test
    fun unknownAlgorithmsThrowIllegalArgument() {
        for (name in listOf("", "HmacMD5", "HmacSHA384", "SHA-256", "Hmac-SHA256", "HmacSHA3-256")) {
            assertFailsWith<IllegalArgumentException>(name) { MacInstance(name, key1) }
        }
        val mac = MacInstance("HmacSHA256", key2)
        assertFailsWith<IllegalArgumentException> { mac.init(key1, "HmacMD5") }
        // A failed init changes nothing.
        mac.update(message2)
        assertEquals(sha256Case2, mac.doFinal().hex())
    }

    @Test
    fun shortOutputThrowsIllegalArgumentAndKeepsTheMessage() {
        for (algorithm in listOf("HmacSHA1", "HmacSHA256", "HmacSHA512")) {
            val mac = MacInstance(algorithm, key2)
            mac.update(message2)
            val length = mac.getMacLength()
            assertFailsWith<IllegalArgumentException>(algorithm) { mac.doFinal(ByteArray(length - 1), 0) }
            assertFailsWith<IllegalArgumentException>(algorithm) { mac.doFinal(ByteArray(length + 2), 3) }
            assertFailsWith<IllegalArgumentException>(algorithm) { mac.doFinal(ByteArray(length + 2), -1) }
            val out = ByteArray(length)
            mac.doFinal(out, 0)
            assertEquals(MacInstance(algorithm, key2).apply { update(message2) }.doFinal().hex(), out.hex(), algorithm)
        }
    }
}
