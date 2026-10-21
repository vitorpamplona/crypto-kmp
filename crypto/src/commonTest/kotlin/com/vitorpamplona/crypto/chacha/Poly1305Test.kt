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
package com.vitorpamplona.crypto.chacha

import com.vitorpamplona.crypto.hexToByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

/**
 * Poly1305 against RFC 8439 Appendix A.3, whose vectors 5 to 11 hit the final reduction
 * and carry paths, plus key-size checks and the incremental state the AEADs use.
 */
class Poly1305Test {
    private fun hex(s: String): ByteArray = s.hexToByteArray()

    private fun zeros(n: Int) = "00".repeat(n)

    private val ietfContribution =
        (
            "Any submission to the IETF intended by the Contributor for publication as all or part of an IETF " +
                "Internet-Draft or RFC and any statement made within the context of an IETF activity is considered " +
                "an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as " +
                "written and electronic communications made at any time or place, which are addressed to"
        ).encodeToByteArray()

    private val jabberwocky =
        (
            "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\n" +
                "All mimsy were the borogoves,\nAnd the mome raths outgrabe."
        ).encodeToByteArray()

    private fun assertMac(
        key: String,
        message: ByteArray,
        tag: String,
    ) = assertContentEquals(hex(tag), Poly1305.mac(message, hex(key)))

    @Test
    fun rfc8439A3Vector1() = assertMac(zeros(32), ByteArray(64), zeros(16))

    @Test
    fun rfc8439A3Vector2() = assertMac(zeros(16) + "36e5f6b5c5e06070f0efca96227a863e", ietfContribution, "36e5f6b5c5e06070f0efca96227a863e")

    @Test
    fun rfc8439A3Vector3() = assertMac("36e5f6b5c5e06070f0efca96227a863e" + zeros(16), ietfContribution, "f3477e7cd95417af89a6b8794c310cf0")

    @Test
    fun rfc8439A3Vector4() = assertMac("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", jabberwocky, "4541669a7eaaee61e708dc7cbcc5eb62")

    // If one uses 130-bit partial reduction, does the code handle the case where partially reduced final result is not fully reduced?
    @Test
    fun rfc8439A3Vector5() = assertMac("02" + zeros(15) + zeros(16), hex("ff".repeat(16)), "03" + zeros(15))

    // What happens if addition of s overflows modulo 2^128?
    @Test
    fun rfc8439A3Vector6() = assertMac("02" + zeros(15) + "ff".repeat(16), hex("02" + zeros(15)), "03" + zeros(15))

    // What happens if data limb is all ones and there is carry from lower limb?
    @Test
    fun rfc8439A3Vector7() = assertMac("01" + zeros(15) + zeros(16), hex("ff".repeat(16) + "f0" + "ff".repeat(15) + "11" + zeros(15)), "05" + zeros(15))

    // What happens if final result from polynomial part is exactly 2^130-5?
    @Test
    fun rfc8439A3Vector8() = assertMac("01" + zeros(15) + zeros(16), hex("ff".repeat(16) + "fb" + "fe".repeat(15) + "01".repeat(16)), zeros(16))

    // What happens if final result from polynomial part is exactly 2^130-6?
    @Test
    fun rfc8439A3Vector9() = assertMac("02" + zeros(15) + zeros(16), hex("fd" + "ff".repeat(15)), "fa" + "ff".repeat(15))

    // What happens if 5*H+L-type reduction produces 131-bit intermediate result?
    @Test
    fun rfc8439A3Vector10() =
        assertMac(
            "01000000000000000400000000000000" + zeros(16),
            hex("e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000" + zeros(16) + "01" + zeros(15)),
            "14000000000000005500000000000000",
        )

    // What happens if 5*H+L-type reduction produces 131-bit final result?
    @Test
    fun rfc8439A3Vector11() =
        assertMac(
            "01000000000000000400000000000000" + zeros(16),
            hex("e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000" + zeros(16)),
            "13" + zeros(15),
        )

    @Test
    fun rejectsKeysThatAreNot32Bytes() {
        for (size in intArrayOf(0, 16, 31, 33, 64)) {
            assertFailsWith<IllegalArgumentException>("key of $size bytes") {
                Poly1305.mac(ByteArray(4), ByteArray(size))
            }
        }
    }

    @Test
    fun incrementalUpdatesMatchOneShot() {
        val key = hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
        val expected = Poly1305.mac(ietfContribution, key)
        for (chunk in intArrayOf(1, 3, 15, 16, 17, 100)) {
            val state = Poly1305State(key)
            var pos = 0
            while (pos < ietfContribution.size) {
                val n = minOf(chunk, ietfContribution.size - pos)
                state.update(ietfContribution, pos, n)
                pos += n
            }
            assertContentEquals(expected, state.finish(), "chunks of $chunk")
        }
    }

    @Test
    fun padToBlockIsZeroPadding() {
        val key = hex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
        val state = Poly1305State(key)
        state.update(jabberwocky, 0, 20)
        state.padToBlock()
        state.padToBlock() // already aligned: no-op
        state.update(jabberwocky, 20, 7)
        state.padToBlock()

        val padded = ByteArray(48)
        jabberwocky.copyInto(padded, 0, 0, 20)
        jabberwocky.copyInto(padded, 32, 20, 27)
        assertContentEquals(Poly1305.mac(padded, key), state.finish())
    }
}
