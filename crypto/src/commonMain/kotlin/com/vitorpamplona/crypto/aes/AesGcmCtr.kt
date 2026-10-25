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
package com.vitorpamplona.crypto.aes

import com.vitorpamplona.crypto.equalsConstantTime

/**
 * A platform's AES, for [CtrGcmKey]: one block in ECB for the hash key, and CTR keystreams.
 * The platform's AES runs on the CPU's AES instructions; GHASH stays the constant-time Kotlin one.
 */
internal interface AesCtr {
    /** E(K, [block]) for one 16-byte block. */
    fun encryptBlock(block: ByteArray): ByteArray

    /**
     * A keystream from the counter block [iv] on. Implementations may count up the whole 128-bit
     * block (CommonCrypto does): [CtrGcmKey] never runs one past a wrap of the low 32 bits.
     */
    fun stream(iv: ByteArray): AesCtrStream
}

/** A running CTR keystream; every [xor] but the last takes whole blocks. [close] frees it. */
internal interface AesCtrStream {
    fun xor(
        input: ByteArray,
        inputOffset: Int,
        length: Int,
        output: ByteArray,
        outputOffset: Int,
    )

    fun close()
}

/**
 * AES-GCM over a platform's [AesCtr], with the Kotlin [Ghash]: the same bytes as [AesGcmKey].
 *
 * GCM's counter is inc32: only the low 32 bits of J0 count, and they wrap to zero without
 * carrying into the 96 above. A platform CTR carries, so a message whose counter wraps (which a
 * nonce of any length but 12 bytes can reach) restarts the keystream at the wrap.
 *
 * The keystream from J0 itself is E(J0), which masks the tag: each call runs one stream from J0
 * over a zero block, then over the message. [decrypt] checks the tag before it decrypts.
 */
internal class CtrGcmKey(
    private val aes: AesCtr,
) : GcmKey {
    private val hashKey = aes.encryptBlock(ByteArray(16))

    override fun encrypt(
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray = encryptFromJ0(gcmJ0(nonce) { hashKey }, plaintext, aad)

    /** [encrypt] from the pre-counter block J0 itself, so a test can start the counter anywhere. */
    fun encryptFromJ0(
        j0: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val out = ByteArray(plaintext.size + AesGcmKey.TAG_LENGTH)
        val encryptedJ0 = ByteArray(16)
        val counter = Counter(j0)
        try {
            counter.xor(ZERO_BLOCK, 0, 16, encryptedJ0, 0)
            counter.xor(plaintext, 0, plaintext.size, out, 0)
        } finally {
            counter.close()
        }
        gcmTag(hashKey, encryptedJ0, aad, out, plaintext.size).copyInto(out, plaintext.size)
        encryptedJ0.fill(0)
        return out
    }

    override fun decrypt(
        nonce: ByteArray,
        input: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(input.size >= AesGcmKey.TAG_LENGTH) { "AES-GCM input is shorter than its tag" }
        val ciphertextLength = input.size - AesGcmKey.TAG_LENGTH
        val counter = Counter(gcmJ0(nonce) { hashKey })
        try {
            val encryptedJ0 = ByteArray(16)
            counter.xor(ZERO_BLOCK, 0, 16, encryptedJ0, 0)
            val expected = gcmTag(hashKey, encryptedJ0, aad, input, ciphertextLength)
            encryptedJ0.fill(0)
            val valid = expected.equalsConstantTime(input.copyOfRange(ciphertextLength, input.size))
            expected.fill(0)
            if (!valid) throw IllegalArgumentException("AES-GCM authentication failed")
            val out = ByteArray(ciphertextLength)
            counter.xor(input, 0, ciphertextLength, out, 0)
            return out
        } finally {
            counter.close()
        }
    }

    /** The GCM keystream from J0: the platform's CTR, restarted where the low 32 bits wrap. */
    private inner class Counter(
        j0: ByteArray,
    ) {
        private val prefix = j0.copyOf(12)

        // Blocks the current stream can give before its low 32 bits would wrap.
        private var blocksLeft =
            0x1_0000_0000L -
                (
                    ((j0[12].toInt() and 0xFF) shl 24) or ((j0[13].toInt() and 0xFF) shl 16) or
                        ((j0[14].toInt() and 0xFF) shl 8) or (j0[15].toInt() and 0xFF)
                ).toUInt().toLong()

        private var stream = aes.stream(j0.copyOf())

        fun xor(
            input: ByteArray,
            inputOffset: Int,
            length: Int,
            output: ByteArray,
            outputOffset: Int,
        ) {
            var done = 0
            while (done < length) {
                if (blocksLeft == 0L) {
                    // inc32 wrapped: the same 96 bits, a counter of zero.
                    stream.close()
                    stream = aes.stream(prefix.copyOf(16))
                    blocksLeft = 0x1_0000_0000L
                }
                val chunk = minOf((length - done).toLong(), blocksLeft * 16).toInt()
                stream.xor(input, inputOffset + done, chunk, output, outputOffset + done)
                blocksLeft -= (chunk + 15) / 16
                done += chunk
            }
        }

        fun close() = stream.close()
    }

    private companion object {
        val ZERO_BLOCK = ByteArray(16)
    }
}
