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
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/** Throws [IllegalArgumentException] if [nonce] is empty; GCM takes any other length. */
internal fun requireGcmNonce(nonce: ByteArray) = require(nonce.isNotEmpty()) { "AES-GCM nonce must not be empty" }

/**
 * Lets an [AESGCM] encrypt once. Its nonce is fixed, and a second message under the same key and
 * nonce would reveal the XOR of the two plaintexts and enough of the hash key to forge tags.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class NonceGuard {
    private val used = AtomicBoolean(false)

    /** Throws [IllegalStateException] on every call after the first, whichever thread makes it. */
    fun claim() =
        check(used.compareAndSet(false, true)) {
            "AES-GCM nonce already used: create a new AESGCM, with a new nonce, for each message"
        }
}

/**
 * One AES key's GCM (NIST SP 800-38D, 128-bit tag): ciphertext followed by the tag, JCA's
 * "AES/GCM/NoPadding" layout. [AesGcmKey] runs it on the bitsliced AES; [CtrGcmKey] on a
 * platform's AES-CTR. [decrypt] throws [IllegalArgumentException] when the tag fails.
 */
internal interface GcmKey {
    fun encrypt(
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray

    fun decrypt(
        nonce: ByteArray,
        input: ByteArray,
        aad: ByteArray,
    ): ByteArray
}

/** The pre-counter block J0 for [nonce] (SP 800-38D §7.1); [hashKey] is asked for only off the 12-byte path. */
internal inline fun gcmJ0(
    nonce: ByteArray,
    hashKey: () -> ByteArray,
): ByteArray {
    requireGcmNonce(nonce)
    if (nonce.size == 12) return nonce.copyOf(16).also { it[15] = 1 }
    val ghash = Ghash(hashKey())
    ghash.update(nonce)
    ghash.updateLengths(0, nonce.size.toLong() * 8)
    return ByteArray(16).also { ghash.digestInto(it) }
}

/** The tag: GHASH over the AAD and the first [ciphertextLength] bytes of [ciphertext], masked with E(J0). */
internal fun gcmTag(
    hashKey: ByteArray,
    encryptedJ0: ByteArray,
    aad: ByteArray,
    ciphertext: ByteArray,
    ciphertextLength: Int,
): ByteArray {
    val ghash = Ghash(hashKey)
    ghash.update(aad)
    ghash.update(ciphertext, 0, ciphertextLength)
    ghash.updateLengths(aad.size.toLong() * 8, ciphertextLength.toLong() * 8)
    val s = ByteArray(16).also { ghash.digestInto(it) }
    for (i in 0 until 16) {
        s[i] = (s[i].toInt() xor encryptedJ0[i].toInt()).toByte()
    }
    return s
}

/**
 * AES-GCM (NIST SP 800-38D) with a 128-bit tag, on [AesBitsliced] and [Ghash]. Output
 * is ciphertext followed by the tag, the same layout JCA's "AES/GCM/NoPadding" uses.
 * Any non-empty nonce length works; a 12-byte one takes the spec's fast path for J0.
 *
 * Holds the key schedule and the hash key H, both computed at construction, so reusing
 * one instance for many messages (each with its own nonce) skips both. It is
 * thread-safe: each call keeps its own scratch.
 *
 * A bitsliced AES call costs the same for one block as for four, so E(J0) for the
 * tag rides in the first counter batch instead of taking a call of its own.
 */
internal class AesGcmKey(
    key: ByteArray,
) : GcmKey {
    private val aes = AesBitsliced(key)

    // H = E(0^128). With a 12-byte nonce the first counter batch computes it alongside E(J0),
    // saving an AES call; other nonce lengths need it before J0, so it's computed on its own.
    // Every thread computes the same bytes, so a race just does the work twice, and @Volatile
    // publishes the array whole.
    @Volatile
    private var computedHashKey: ByteArray? = null

    private val hashKey: ByteArray
        get() =
            computedHashKey ?: ByteArray(16).also {
                val scratch = AesBitsliced.Scratch()
                aes.encryptBlocks(it, 0, it, 0, 1, scratch)
                scratch.clear()
                computedHashKey = it
            }

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
        val call = Call(j0)
        val out = ByteArray(plaintext.size + TAG_LENGTH)
        call.ctr(plaintext, plaintext.size, out)
        call.tag(aad, out, plaintext.size).copyInto(out, plaintext.size)
        call.clear()
        return out
    }

    /** Throws [IllegalArgumentException] when the tag does not verify; no plaintext is returned then. */
    override fun decrypt(
        nonce: ByteArray,
        input: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(input.size >= TAG_LENGTH) { "AES-GCM input is shorter than its tag" }
        val call = Call(gcmJ0(nonce) { hashKey })
        val ciphertextLength = input.size - TAG_LENGTH
        val out = ByteArray(ciphertextLength)
        call.ctr(input, ciphertextLength, out)
        val expected = call.tag(aad, input, ciphertextLength)
        call.clear()
        val valid = expected.equalsConstantTime(input.copyOfRange(ciphertextLength, input.size))
        expected.fill(0)
        if (!valid) {
            out.fill(0)
            throw IllegalArgumentException("AES-GCM authentication failed")
        }
        return out
    }

    /** One encryption or decryption: its J0, the E(J0) the counter pass produces, and scratch. */
    private inner class Call(
        val j0: ByteArray,
    ) {
        val scratch = AesBitsliced.Scratch()
        val encryptedJ0 = ByteArray(16)

        /**
         * XORs [input] with the keystream from inc32(J0) on, four blocks per AES call.
         * The first call also encrypts J0. The counter is the low 32 bits of J0 and
         * wraps around without carrying into the rest (inc32).
         */
        fun ctr(
            input: ByteArray,
            length: Int,
            out: ByteArray,
        ) {
            val blocks = ByteArray(64)
            val keystream = ByteArray(64)
            var counter =
                ((j0[12].toInt() and 0xFF) shl 24) or ((j0[13].toInt() and 0xFF) shl 16) or
                    ((j0[14].toInt() and 0xFF) shl 8) or (j0[15].toInt() and 0xFF)

            var pos = 0
            var first = true
            // The all-zero block in slot 0 of the first batch encrypts to H.
            val computeHashKey = computedHashKey == null
            while (first || pos < length) {
                var slot = 0
                if (first) {
                    if (computeHashKey) slot++
                    j0.copyInto(blocks, 16 * slot)
                    slot++
                }
                val dataSlot = slot
                while (slot < 4 && pos + 16 * (slot - dataSlot) < length) {
                    counter++
                    val o = 16 * slot
                    j0.copyInto(blocks, o, 0, 12)
                    blocks[o + 12] = (counter ushr 24).toByte()
                    blocks[o + 13] = (counter ushr 16).toByte()
                    blocks[o + 14] = (counter ushr 8).toByte()
                    blocks[o + 15] = counter.toByte()
                    slot++
                }
                aes.encryptBlocks(blocks, 0, keystream, 0, slot, scratch)
                if (first) {
                    if (computeHashKey) computedHashKey = keystream.copyOf(16)
                    keystream.copyInto(encryptedJ0, 0, 16 * (dataSlot - 1), 16 * dataSlot)
                }

                val chunk = minOf(16 * (slot - dataSlot), length - pos)
                val k = 16 * dataSlot
                for (i in 0 until chunk) {
                    out[pos + i] = (input[pos + i].toInt() xor keystream[k + i].toInt()).toByte()
                }
                pos += chunk
                first = false
            }
            keystream.fill(0)
        }

        /** GHASH over the AAD and ciphertext, masked with E(J0). Call after [ctr]. */
        fun tag(
            aad: ByteArray,
            ciphertext: ByteArray,
            ciphertextLength: Int,
        ): ByteArray = gcmTag(hashKey, encryptedJ0, aad, ciphertext, ciphertextLength)

        /** Zeroes the scratch and E(J0) once the call is done with them. */
        fun clear() {
            scratch.clear()
            encryptedJ0.fill(0)
        }
    }

    companion object {
        const val TAG_LENGTH = 16
    }
}
