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

/**
 * Pure Kotlin implementation of ChaCha20, HChaCha20, and XChaCha20.
 *
 * All functions are stateless and thread-safe — they use only local variables
 * and produce no side effects beyond their return values. Every function checks the
 * key, nonce and input sizes and throws [IllegalArgumentException] on a wrong one, so a
 * key and nonce passed in each other's place fail instead of encrypting.
 *
 * The block counter is RFC 8439's unsigned 32-bit number carried in an [Int]: 0 to
 * [Int.MAX_VALUE] are themselves, and negative values are 2^31 to 2^32 - 1 (so -1 is
 * block 0xffffffff, the last one). A message that would need blocks past 2^32 - 1 is
 * rejected rather than wrapped round to block 0, which would reuse keystream.
 *
 * References:
 * - RFC 8439: ChaCha20 and Poly1305
 * - draft-irtf-cfrg-xchacha: XChaCha20 (HChaCha20 + ChaCha20)
 */
public object ChaCha20Core {
    // "expand 32-byte k" as little-endian integers
    private const val SIGMA0 = 0x61707865
    private const val SIGMA1 = 0x3320646e
    private const val SIGMA2 = 0x79622d32
    private const val SIGMA3 = 0x6b206574

    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 12
    private const val X_NONCE_SIZE = 24
    private const val H_INPUT_SIZE = 16
    private const val BLOCK_SIZE = 64

    /** Number of distinct 32-bit block counters. */
    private const val COUNTER_SPACE = 1L shl 32

    /**
     * The 20 ChaCha rounds (RFC 8439 §2.3) over [input] into [output], adding [input] word by
     * word when [addInput] (the block function) and not for HChaCha20. [output] may be [input].
     * The state lives in 16 locals rather than an array, so it stays in registers through
     * the rounds.
     */
    private fun chaCha20Rounds(
        input: IntArray,
        output: IntArray,
        addInput: Boolean,
    ) {
        var x0 = input[0]
        var x1 = input[1]
        var x2 = input[2]
        var x3 = input[3]
        var x4 = input[4]
        var x5 = input[5]
        var x6 = input[6]
        var x7 = input[7]
        var x8 = input[8]
        var x9 = input[9]
        var x10 = input[10]
        var x11 = input[11]
        var x12 = input[12]
        var x13 = input[13]
        var x14 = input[14]
        var x15 = input[15]
        for (round in 0 until 10) {
            // Column rounds
            x0 += x4
            x12 = (x12 xor x0).rotateLeft(16)
            x8 += x12
            x4 = (x4 xor x8).rotateLeft(12)
            x0 += x4
            x12 = (x12 xor x0).rotateLeft(8)
            x8 += x12
            x4 = (x4 xor x8).rotateLeft(7)
            x1 += x5
            x13 = (x13 xor x1).rotateLeft(16)
            x9 += x13
            x5 = (x5 xor x9).rotateLeft(12)
            x1 += x5
            x13 = (x13 xor x1).rotateLeft(8)
            x9 += x13
            x5 = (x5 xor x9).rotateLeft(7)
            x2 += x6
            x14 = (x14 xor x2).rotateLeft(16)
            x10 += x14
            x6 = (x6 xor x10).rotateLeft(12)
            x2 += x6
            x14 = (x14 xor x2).rotateLeft(8)
            x10 += x14
            x6 = (x6 xor x10).rotateLeft(7)
            x3 += x7
            x15 = (x15 xor x3).rotateLeft(16)
            x11 += x15
            x7 = (x7 xor x11).rotateLeft(12)
            x3 += x7
            x15 = (x15 xor x3).rotateLeft(8)
            x11 += x15
            x7 = (x7 xor x11).rotateLeft(7)
            // Diagonal rounds
            x0 += x5
            x15 = (x15 xor x0).rotateLeft(16)
            x10 += x15
            x5 = (x5 xor x10).rotateLeft(12)
            x0 += x5
            x15 = (x15 xor x0).rotateLeft(8)
            x10 += x15
            x5 = (x5 xor x10).rotateLeft(7)
            x1 += x6
            x12 = (x12 xor x1).rotateLeft(16)
            x11 += x12
            x6 = (x6 xor x11).rotateLeft(12)
            x1 += x6
            x12 = (x12 xor x1).rotateLeft(8)
            x11 += x12
            x6 = (x6 xor x11).rotateLeft(7)
            x2 += x7
            x13 = (x13 xor x2).rotateLeft(16)
            x8 += x13
            x7 = (x7 xor x8).rotateLeft(12)
            x2 += x7
            x13 = (x13 xor x2).rotateLeft(8)
            x8 += x13
            x7 = (x7 xor x8).rotateLeft(7)
            x3 += x4
            x14 = (x14 xor x3).rotateLeft(16)
            x9 += x14
            x4 = (x4 xor x9).rotateLeft(12)
            x3 += x4
            x14 = (x14 xor x3).rotateLeft(8)
            x9 += x14
            x4 = (x4 xor x9).rotateLeft(7)
        }
        if (addInput) {
            output[0] = x0 + input[0]
            output[1] = x1 + input[1]
            output[2] = x2 + input[2]
            output[3] = x3 + input[3]
            output[4] = x4 + input[4]
            output[5] = x5 + input[5]
            output[6] = x6 + input[6]
            output[7] = x7 + input[7]
            output[8] = x8 + input[8]
            output[9] = x9 + input[9]
            output[10] = x10 + input[10]
            output[11] = x11 + input[11]
            output[12] = x12 + input[12]
            output[13] = x13 + input[13]
            output[14] = x14 + input[14]
            output[15] = x15 + input[15]
        } else {
            output[0] = x0
            output[1] = x1
            output[2] = x2
            output[3] = x3
            output[4] = x4
            output[5] = x5
            output[6] = x6
            output[7] = x7
            output[8] = x8
            output[9] = x9
            output[10] = x10
            output[11] = x11
            output[12] = x12
            output[13] = x13
            output[14] = x14
            output[15] = x15
        }
    }

    private fun requireKeyAndNonce(
        key: ByteArray,
        nonce: ByteArray,
    ) {
        require(key.size == KEY_SIZE) { "ChaCha20 key must be $KEY_SIZE bytes, was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "ChaCha20 nonce must be $NONCE_SIZE bytes, was ${nonce.size}" }
    }

    /** A state with the constants and [key] in words 0-11; the caller fills words 12-15. */
    private fun keyedState(key: ByteArray): IntArray {
        val state = IntArray(16)
        state[0] = SIGMA0
        state[1] = SIGMA1
        state[2] = SIGMA2
        state[3] = SIGMA3
        for (i in 0..7) {
            state[4 + i] = key.littleEndianToInt(4 * i)
        }
        return state
    }

    /**
     * Initialize the ChaCha20 state matrix from key, counter, and nonce.
     * Layout (RFC 8439 §2.3):
     *   cccccccc  cccccccc  cccccccc  cccccccc
     *   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     *   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     *   bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
     */
    private fun initState(
        key: ByteArray,
        counter: Int,
        nonce: ByteArray,
    ): IntArray {
        val state = keyedState(key)
        state[12] = counter
        state[13] = nonce.littleEndianToInt(0)
        state[14] = nonce.littleEndianToInt(4)
        state[15] = nonce.littleEndianToInt(8)
        return state
    }

    /**
     * ChaCha20 block function (RFC 8439 §2.3).
     * Produces a 64-byte keystream block.
     *
     * @param key 32-byte key
     * @param counter block counter, unsigned 32-bit (see [ChaCha20Core])
     * @param nonce 12-byte nonce (IETF variant)
     * @return 64-byte keystream block
     */
    public fun chaCha20Block(
        key: ByteArray,
        counter: Int,
        nonce: ByteArray,
    ): ByteArray {
        requireKeyAndNonce(key, nonce)
        val initial = initState(key, counter, nonce)
        val working = IntArray(16)
        chaCha20Rounds(initial, working, addInput = true)

        val output = ByteArray(64)
        for (i in 0..15) {
            working[i].intToLittleEndian(output, i * 4)
        }
        initial.fill(0)
        working.fill(0)
        return output
    }

    /**
     * ChaCha20 IETF stream cipher XOR (RFC 8439 §2.4).
     * XORs the message with the ChaCha20 keystream.
     *
     * @param message plaintext or ciphertext
     * @param key 32-byte key
     * @param nonce 12-byte nonce
     * @param counter initial block counter (0 for stream cipher, 1 for AEAD), unsigned
     *   32-bit (see [ChaCha20Core]); the message must end by block 2^32 - 1
     * @return XOR'd output (same length as message)
     */
    public fun chaCha20Xor(
        message: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        counter: Int = 0,
    ): ByteArray {
        val output = ByteArray(message.size)
        chaCha20XorInto(message, 0, message.size, output, 0, key, nonce, counter)
        return output
    }

    /**
     * [chaCha20Xor] of `input[inputOffset until inputOffset + length]` into [output] at
     * [outputOffset], so the AEADs can read and write around their tag without copies.
     *
     * Parses key/nonce once and reuses the state across blocks.
     * Full 64-byte blocks use word-level XOR (4 bytes at a time).
     */
    internal fun chaCha20XorInto(
        input: ByteArray,
        inputOffset: Int,
        length: Int,
        output: ByteArray,
        outputOffset: Int,
        key: ByteArray,
        nonce: ByteArray,
        counter: Int,
    ) {
        requireKeyAndNonce(key, nonce)
        val blocksNeeded = (length.toLong() + BLOCK_SIZE - 1) / BLOCK_SIZE
        require(counter.toUInt().toLong() + blocksNeeded <= COUNTER_SPACE) {
            "ChaCha20 block counter would pass 2^32 - 1: $blocksNeeded blocks from counter ${counter.toUInt()}"
        }
        if (length == 0) return

        val fullBlocks = length / BLOCK_SIZE
        val remainder = length % BLOCK_SIZE

        // Parse key and nonce once into the initial state template
        val initial = initState(key, counter, nonce)
        val working = IntArray(16)

        // The check above keeps counter + i within 32 bits, so Int's wrapping add is exact.
        for (i in 0 until fullBlocks) {
            initial[12] = counter + i
            chaCha20Rounds(initial, working, addInput = true)

            // XOR at word level: read 4 message bytes as Int, XOR with keystream word, write 4 bytes
            val inOff = inputOffset + i * BLOCK_SIZE
            val outOff = outputOffset + i * BLOCK_SIZE
            for (j in 0..15) {
                val mw = input.littleEndianToInt(inOff + j * 4)
                (working[j] xor mw).intToLittleEndian(output, outOff + j * 4)
            }
        }

        if (remainder > 0) {
            initial[12] = counter + fullBlocks
            chaCha20Rounds(initial, working, addInput = true)

            val inOff = inputOffset + fullBlocks * BLOCK_SIZE
            val outOff = outputOffset + fullBlocks * BLOCK_SIZE
            // Process full words within the remainder
            val fullWords = remainder / 4
            for (j in 0 until fullWords) {
                val mw = input.littleEndianToInt(inOff + j * 4)
                (working[j] xor mw).intToLittleEndian(output, outOff + j * 4)
            }
            // Process remaining bytes (0-3 bytes) from one more keystream word
            val tailStart = fullWords * 4
            if (tailStart < remainder) {
                val ks = working[fullWords]
                for (b in tailStart until remainder) {
                    val ksByte = ks ushr (8 * (b - tailStart))
                    output[outOff + b] = (input[inOff + b].toInt() xor ksByte).toByte()
                }
            }
        }

        initial.fill(0)
        working.fill(0)
    }

    /**
     * HChaCha20 (draft-irtf-cfrg-xchacha §2.2).
     * Derives a 32-byte subkey from a 32-byte key and 16-byte input.
     * Used as the first step of XChaCha20.
     *
     * @param key 32-byte key
     * @param input 16-byte input (first 16 bytes of the 24-byte XChaCha20 nonce)
     * @return 32-byte subkey
     */
    public fun hChaCha20(
        key: ByteArray,
        input: ByteArray,
    ): ByteArray {
        require(key.size == KEY_SIZE) { "HChaCha20 key must be $KEY_SIZE bytes, was ${key.size}" }
        require(input.size == H_INPUT_SIZE) { "HChaCha20 input must be $H_INPUT_SIZE bytes, was ${input.size}" }
        return hChaCha20Unchecked(key, input)
    }

    /** HChaCha20 over the first 16 bytes of [input]; the caller has checked the sizes. */
    private fun hChaCha20Unchecked(
        key: ByteArray,
        input: ByteArray,
    ): ByteArray {
        val state = keyedState(key)
        state[12] = input.littleEndianToInt(0)
        state[13] = input.littleEndianToInt(4)
        state[14] = input.littleEndianToInt(8)
        state[15] = input.littleEndianToInt(12)

        chaCha20Rounds(state, state, addInput = false)

        // Output words 0-3 and 12-15 (skip the key material in 4-11)
        val output = ByteArray(32)
        state[0].intToLittleEndian(output, 0)
        state[1].intToLittleEndian(output, 4)
        state[2].intToLittleEndian(output, 8)
        state[3].intToLittleEndian(output, 12)
        state[12].intToLittleEndian(output, 16)
        state[13].intToLittleEndian(output, 20)
        state[14].intToLittleEndian(output, 24)
        state[15].intToLittleEndian(output, 28)
        state.fill(0)
        return output
    }

    /**
     * XChaCha20's subkey: HChaCha20 of [key] and the first 16 bytes of the 24-byte [nonce]
     * (draft-irtf-cfrg-xchacha §2.3). The caller zeroes it when done.
     */
    internal fun xChaCha20SubKey(
        key: ByteArray,
        nonce: ByteArray,
    ): ByteArray {
        require(key.size == KEY_SIZE) { "XChaCha20 key must be $KEY_SIZE bytes, was ${key.size}" }
        require(nonce.size == X_NONCE_SIZE) { "XChaCha20 nonce must be $X_NONCE_SIZE bytes, was ${nonce.size}" }
        return hChaCha20Unchecked(key, nonce)
    }

    /** XChaCha20's 12-byte subnonce: 4 zero bytes, then the last 8 bytes of the 24-byte [nonce]. */
    internal fun xChaCha20SubNonce(nonce: ByteArray): ByteArray {
        val subNonce = ByteArray(NONCE_SIZE)
        nonce.copyInto(subNonce, destinationOffset = 4, startIndex = 16, endIndex = 24)
        return subNonce
    }

    /**
     * Generates the first 32 bytes of keystream block 0 (used as Poly1305 one-time key).
     * Avoids allocating a full 64-byte block.
     */
    internal fun chaCha20PolyKey(
        key: ByteArray,
        nonce: ByteArray,
    ): ByteArray {
        requireKeyAndNonce(key, nonce)
        val initial = initState(key, 0, nonce)
        val working = IntArray(16)
        chaCha20Rounds(initial, working, addInput = true)

        val polyKey = ByteArray(32)
        for (i in 0..7) {
            working[i].intToLittleEndian(polyKey, i * 4)
        }
        initial.fill(0)
        working.fill(0)
        return polyKey
    }

    /**
     * XChaCha20 stream cipher XOR (draft-irtf-cfrg-xchacha §2.3).
     * Uses HChaCha20 to derive a subkey, then applies ChaCha20 with the remaining nonce bytes.
     *
     * Note the argument order, (message, nonce, key), differs from [chaCha20Xor]'s.
     *
     * @param message plaintext or ciphertext
     * @param nonce 24-byte nonce
     * @param key 32-byte key
     * @return XOR'd output (same length as message)
     */
    public fun xChaCha20Xor(
        message: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray {
        val subKey = xChaCha20SubKey(key, nonce)
        val output = chaCha20Xor(message, subKey, xChaCha20SubNonce(nonce), counter = 0)
        subKey.fill(0)
        return output
    }
}

// --- Little-endian conversion helpers ---

internal fun ByteArray.littleEndianToInt(offset: Int): Int =
    (this[offset].toInt() and 0xFF) or
        ((this[offset + 1].toInt() and 0xFF) shl 8) or
        ((this[offset + 2].toInt() and 0xFF) shl 16) or
        ((this[offset + 3].toInt() and 0xFF) shl 24)

internal fun Int.intToLittleEndian(
    output: ByteArray,
    offset: Int,
) {
    output[offset] = (this and 0xFF).toByte()
    output[offset + 1] = (this ushr 8 and 0xFF).toByte()
    output[offset + 2] = (this ushr 16 and 0xFF).toByte()
    output[offset + 3] = (this ushr 24 and 0xFF).toByte()
}
