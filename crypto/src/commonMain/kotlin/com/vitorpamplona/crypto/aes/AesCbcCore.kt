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

/** Throws [IllegalArgumentException] unless [iv] is a 16-byte AES-CBC IV. */
internal fun requireCbcIv(iv: ByteArray) = require(iv.size == 16) { "AES-CBC IV must be 16 bytes, was ${iv.size}" }

/**
 * AES-CBC without padding (NIST SP 800-38A §6.2), matching JCA's "AES/CBC/NoPadding": the
 * block-cipher half of [AESCBC] on Linux, which [cbcEncrypt] and [cbcDecrypt] wrap in PKCS#7.
 * Both directions take whole 16-byte blocks and a 16-byte IV; the callers check.
 *
 * Holds the key schedule, so one instance serves many messages; it is thread-safe.
 */
internal class AesCbcKey(
    key: ByteArray,
) {
    private val aes = AesBitsliced(key)

    fun encrypt(
        iv: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val scratch = AesBitsliced.Scratch()
        val out = plaintext.copyOf()
        var prev = iv
        var prevOffset = 0
        for (o in out.indices step 16) {
            for (i in 0 until 16) {
                out[o + i] = (out[o + i].toInt() xor prev[prevOffset + i].toInt()).toByte()
            }
            aes.encryptBlocks(out, o, out, o, 1, scratch)
            prev = out
            prevOffset = o
        }
        scratch.clear()
        return out
    }

    fun decrypt(
        iv: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        val scratch = AesBitsliced.Scratch()
        val out = ByteArray(ciphertext.size)
        var o = 0
        while (o < ciphertext.size) {
            val blocks = minOf(4, (ciphertext.size - o) / 16)
            aes.decryptBlocks(ciphertext, o, out, o, blocks, scratch)
            o += 16 * blocks
        }
        scratch.clear()
        for (i in 0 until minOf(16, out.size)) {
            out[i] = (out[i].toInt() xor iv[i].toInt()).toByte()
        }
        for (i in 16 until out.size) {
            out[i] = (out[i].toInt() xor ciphertext[i - 16].toInt()).toByte()
        }
        return out
    }
}

/**
 * AES-CBC encryption with PKCS#7 padding, for every platform's [AESCBC]: pads [plaintext] to
 * whole blocks, hands them to [encryptBlocks] (a CBC encryption without padding that returns a
 * new array) and zeroes the padded copy.
 */
internal inline fun cbcEncrypt(
    plaintext: ByteArray,
    encryptBlocks: (ByteArray) -> ByteArray,
): ByteArray {
    val pad = 16 - plaintext.size % 16
    val padded = plaintext.copyOf(plaintext.size + pad)
    padded.fill(pad.toByte(), plaintext.size, padded.size)
    try {
        return encryptBlocks(padded)
    } finally {
        padded.fill(0)
    }
}

/**
 * AES-CBC decryption with PKCS#7 padding, for every platform's [AESCBC], and the one place its
 * lengths are checked: throws [IllegalArgumentException] unless [ciphertext] is a non-empty
 * multiple of 16 bytes, then hands it to [decryptBlocks] (a CBC decryption without padding that
 * returns a new array) and strips the padding with [stripPkcs7].
 */
internal inline fun cbcDecrypt(
    ciphertext: ByteArray,
    decryptBlocks: (ByteArray) -> ByteArray,
): ByteArray {
    require(ciphertext.isNotEmpty() && ciphertext.size % 16 == 0) {
        "AES-CBC ciphertext must be a non-empty multiple of 16 bytes, was ${ciphertext.size}"
    }
    return stripPkcs7(decryptBlocks(ciphertext))
}

/**
 * Removes the PKCS#7 padding from [padded], a non-empty whole number of decrypted 16-byte
 * blocks, checking every byte of the last block with no early exit. Returns the plaintext in a
 * new array and zeroes [padded]. On bad padding it throws [IllegalArgumentException], so a
 * caller never sees the unauthenticated plaintext.
 */
internal fun stripPkcs7(padded: ByteArray): ByteArray {
    val pad = padded[padded.size - 1].toInt() and 0xFF
    var bad = ((pad - 1) ushr 31) or ((16 - pad) ushr 31)
    for (i in 1..16) {
        val inPad = (i - pad - 1) ushr 31
        val differs = ((padded[padded.size - i].toInt() and 0xFF) xor pad).let { (it or -it) ushr 31 }
        bad = bad or (inPad and differs)
    }
    if (bad != 0) {
        padded.fill(0)
        throw IllegalArgumentException("AES-CBC padding is invalid")
    }
    val plaintext = padded.copyOf(padded.size - pad)
    padded.fill(0)
    return plaintext
}
