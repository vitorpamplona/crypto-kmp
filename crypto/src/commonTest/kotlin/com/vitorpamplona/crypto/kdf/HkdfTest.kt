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
package com.vitorpamplona.crypto.kdf

import com.vitorpamplona.crypto.hexToByteArray
import com.vitorpamplona.crypto.sha2.sha256
import com.vitorpamplona.crypto.sha2.sha384
import com.vitorpamplona.crypto.toHexKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * RFC 5869 Appendix A (SHA-256 cases 1-3), an HMAC-SHA512 case, the output-length limits,
 * and RFC 9001 Appendix A.1 for [Hkdf.expandLabel]. The SHA-512 and full-length values were
 * computed independently with Python's `hmac` module.
 */
class HkdfTest {
    private val ikm = ByteArray(22) { 0x0b }
    private val salt = "000102030405060708090a0b0c".hexToByteArray()
    private val info = "f0f1f2f3f4f5f6f7f8f9".hexToByteArray()
    private val prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    private val okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

    private fun range(
        from: Int,
        until: Int,
    ) = ByteArray(until - from) { (from + it).toByte() }

    @Test
    fun extractAndExpand() {
        val hkdf = Hkdf()
        val extracted = hkdf.extract(ikm, salt)
        assertEquals(prk, extracted.toHexKey())
        assertEquals(okm, hkdf.expand(extracted, info, 42).toHexKey())
    }

    @Test
    fun rfc5869Case2LongerInputsAndOutput() {
        val hkdf = Hkdf()
        val extracted = hkdf.extract(range(0x00, 0x50), range(0x60, 0xb0))
        assertEquals("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", extracted.toHexKey())
        assertEquals(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f1d87",
            hkdf.expand(extracted, range(0xb0, 0x100), 82).toHexKey(),
        )
    }

    @Test
    fun rfc5869Case3EmptySaltAndInfo() {
        // An empty salt is HMAC with an empty key, which pads to the same block as the
        // HashLen zeros RFC 5869 prescribes.
        val hkdf = Hkdf()
        val extracted = hkdf.extract(ikm, ByteArray(0))
        assertEquals("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", extracted.toHexKey())
        assertEquals(extracted.toHexKey(), hkdf.extract(ikm, ByteArray(32)).toHexKey())
        assertEquals(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            hkdf.expand(extracted, ByteArray(0), 42).toHexKey(),
        )
    }

    @Test
    fun sha512WithCase1Inputs() {
        val hkdf = Hkdf("HmacSHA512")
        assertEquals(64, hkdf.hashLen)
        val extracted = hkdf.extract(ikm, salt)
        assertEquals(
            "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26" +
                "c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            extracted.toHexKey(),
        )
        assertEquals(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
            hkdf.expand(extracted, info, 42).toHexKey(),
        )
    }

    @Test
    fun extractOfTwoPartsMatchesTheirConcatenation() {
        val hkdf = Hkdf()
        assertEquals(prk, hkdf.extract(ikm.copyOfRange(0, 9), ikm.copyOfRange(9, 22), salt).toHexKey())
    }

    @Test
    fun hashLenFollowsTheAlgorithm() {
        assertEquals(32, Hkdf().hashLen)
        assertEquals(32, Hkdf("HmacSHA256").hashLen)
        assertEquals(48, Hkdf("HmacSHA384").hashLen)
        assertEquals(64, Hkdf("HmacSHA512").hashLen)
        assertEquals(20, Hkdf("HmacSHA1").hashLen)
        assertFailsWith<IllegalArgumentException> { Hkdf("HmacMD5") }
        assertFailsWith<IllegalArgumentException> { Hkdf("SHA-256") }
    }

    @Test
    fun tls13Sha384KeySchedule() {
        // TLS_AES_256_GCM_SHA384's early secret and the first derived secret and traffic key and IV
        // off it (RFC 8446 §7.1), checked against an HKDF written independently in Python.
        val hkdf = Hkdf("HmacSHA384")
        val early = hkdf.extract(ByteArray(48), ByteArray(48))
        assertEquals("7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5", early.toHexKey())
        val derived = hkdf.expandLabel(early, "derived", sha384(ByteArray(0)), 48)
        assertEquals("1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b", derived.toHexKey())
        assertEquals("6f9ba9cd492bbbdd7adc49c726f736b11b5fd46efc71b929f0aa2c19e98d4b84", hkdf.expandLabel(derived, "key", ByteArray(0), 32).toHexKey())
        assertEquals("0159e8dce065587017ea5a82", hkdf.expandLabel(derived, "iv", ByteArray(0), 12).toHexKey())
    }

    @Test
    fun zeroLengthOutput() {
        assertEquals(0, Hkdf().expand(prk.hexToByteArray(), info, 0).size)
        assertEquals(0, Hkdf("HmacSHA512").expand(prk.hexToByteArray(), info, 0).size)
        assertFailsWith<IllegalArgumentException> { Hkdf().expand(prk.hexToByteArray(), info, -1) }
    }

    @Test
    fun outputOfExactly255Blocks() {
        // The counter byte reaches 255 and must not wrap. Checked through a digest of the
        // output plus its last bytes, both computed independently.
        val sha256 = Hkdf()
        val full256 = sha256.expand(sha256.extract(ikm, salt), info, 255 * 32)
        assertEquals(8160, full256.size)
        assertEquals("06ce7419405a88a66ba5c9795579cb05130c85101924d187552a0f7f57deb091", sha256(full256).toHexKey())
        assertEquals("4d48a6d1b981d7e523d5c0f22154ee88", full256.copyOfRange(8144, 8160).toHexKey())

        val sha512 = Hkdf("HmacSHA512")
        val full512 = sha512.expand(sha512.extract(ikm, salt), info, 255 * 64)
        assertEquals(16320, full512.size)
        assertEquals("d623a5f5bc03bad6fef4c74bef4bf03770338d155b256c333cae9a3ca8f77e45", sha256(full512).toHexKey())
        assertEquals("cc54a28763012fec34d40b7c12ee8560", full512.copyOfRange(16304, 16320).toHexKey())
    }

    @Test
    fun rejectsOutputLongerThan255Blocks() {
        assertFailsWith<IllegalArgumentException> { Hkdf().expand(prk.hexToByteArray(), info, 255 * 32 + 1) }
        assertFailsWith<IllegalArgumentException> { Hkdf("HmacSHA512").expand(prk.hexToByteArray(), info, 255 * 64 + 1) }
    }

    @Test
    fun expandLabelDerivesTheRfc9001InitialSecrets() {
        // RFC 9001 Appendix A.1: the client and server initial secrets, keys, IVs and
        // header-protection keys for destination connection ID 0x8394c8f03e515708.
        val hkdf = Hkdf()
        val initialSalt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a".hexToByteArray()
        val initial = hkdf.extract("8394c8f03e515708".hexToByteArray(), initialSalt)
        assertEquals("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", initial.toHexKey())

        val client = hkdf.expandLabel(initial, "client in", ByteArray(0), 32)
        assertEquals("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", client.toHexKey())
        assertEquals("1f369613dd76d5467730efcbe3b1a22d", hkdf.expandLabel(client, "quic key", ByteArray(0), 16).toHexKey())
        assertEquals("fa044b2f42a3fd3b46fb255c", hkdf.expandLabel(client, "quic iv", ByteArray(0), 12).toHexKey())
        assertEquals("9f50449e04a0e810283a1e9933adedd2", hkdf.expandLabel(client, "quic hp", ByteArray(0), 16).toHexKey())

        val server = hkdf.expandLabel(initial, "server in", ByteArray(0), 32)
        assertEquals("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", server.toHexKey())
        assertEquals("cf3a5331653c364c88f0f379b6067e37", hkdf.expandLabel(server, "quic key", ByteArray(0), 16).toHexKey())
        assertEquals("0ac1493ca1905853b0bba03e", hkdf.expandLabel(server, "quic iv", ByteArray(0), 12).toHexKey())
        assertEquals("c206b8d9b9f0f37644430b490eeaa314", hkdf.expandLabel(server, "quic hp", ByteArray(0), 16).toHexKey())
    }

    @Test
    fun expandLabelBuildsTheHkdfLabelStructure() {
        // HkdfLabel = uint16 length || uint8 len || "tls13 " + label || uint8 len || context.
        val hkdf = Hkdf()
        val secret = prk.hexToByteArray()
        val context = "0102".hexToByteArray()
        val label = "002010746c7331332074657374206c6162656c020102".hexToByteArray()
        assertEquals(hkdf.expand(secret, label, 32).toHexKey(), hkdf.expandLabel(secret, "test label", context, 32).toHexKey())
        assertFailsWith<IllegalArgumentException> { hkdf.expandLabel(secret, "x".repeat(250), ByteArray(0), 32) }
        assertFailsWith<IllegalArgumentException> { hkdf.expandLabel(secret, "x", ByteArray(256), 32) }
    }
}
