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

import com.vitorpamplona.crypto.equalsConstantTime

/**
 * Standard ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) with 12-byte nonces.
 *
 * Unlike [XChaCha20Poly1305] which uses 24-byte nonces via HChaCha20,
 * this operates directly with the IETF ChaCha20 variant.
 *
 * Construction:
 * 1. Generate Poly1305 OTK from ChaCha20 block 0
 * 2. Encrypt with ChaCha20 starting at counter 1
 * 3. Compute Poly1305 tag over: pad16(ad) || pad16(ciphertext) || len(ad) || len(ct)
 *
 * A wrong key or nonce size throws [IllegalArgumentException]; so does [decrypt] when the
 * input is shorter than the tag or the tag does not verify, where [decryptOrNull] returns
 * null instead. No plaintext is produced before the tag verifies.
 *
 * On Android API 28+ this is the platform's ChaCha20-Poly1305 (BoringSSL), and on a JVM it is
 * SunJCE's when HotSpot runs it with vector instructions (JDK 20+ on a CPU with them) or a
 * bundled Conscrypt's; everywhere else, including Java 17, it is the Kotlin implementation
 * here, which is faster than the JDK's pure-Java one. Both give the same bytes.
 */
public object ChaCha20Poly1305 {
    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 12
    private const val TAG_SIZE = 16

    /**
     * AEAD encrypt.
     *
     * @param plaintext message to encrypt
     * @param ad associated data (authenticated but not encrypted)
     * @param nonce 12-byte nonce
     * @param key 32-byte key
     * @return ciphertext || 16-byte tag
     */
    public fun encrypt(
        plaintext: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray {
        requireKeyAndNonce(key, nonce)
        platformChaCha20Poly1305?.let { return it.seal(plaintext, ad, nonce, key) }
        return kotlinSeal(plaintext, ad, nonce, key)
    }

    /** The Kotlin seal, for sizes already checked: what every platform without JCA's runs. */
    internal fun kotlinSeal(
        plaintext: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray {
        // Step 1: Generate Poly1305 one-time key
        val polyKey = ChaCha20Core.chaCha20PolyKey(key, nonce)

        // Step 2: Encrypt plaintext with counter starting at 1, straight into the output
        val result = ByteArray(plaintext.size + TAG_SIZE)
        ChaCha20Core.chaCha20XorInto(plaintext, 0, plaintext.size, result, 0, key, nonce, counter = 1)

        // Step 3: Compute tag and append it: ciphertext || tag
        computeTag(polyKey, ad, result, plaintext.size).copyInto(result, plaintext.size)
        polyKey.fill(0)
        return result
    }

    /**
     * AEAD decrypt.
     *
     * @param ciphertextWithTag ciphertext || 16-byte tag
     * @param ad associated data
     * @param nonce 12-byte nonce
     * @param key 32-byte key
     * @return plaintext
     * @throws IllegalArgumentException if the input is shorter than the tag or the tag does not verify
     */
    public fun decrypt(
        ciphertextWithTag: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray {
        requireKeyAndNonce(key, nonce)
        require(ciphertextWithTag.size >= TAG_SIZE) { "ChaCha20-Poly1305 input is shorter than its $TAG_SIZE-byte tag" }
        return open(ciphertextWithTag, ad, nonce, key)
            ?: throw IllegalArgumentException("ChaCha20-Poly1305 authentication failed")
    }

    /**
     * [decrypt], but returns null when the input is shorter than the tag or the tag does not
     * verify. A wrong key or nonce size still throws.
     */
    public fun decryptOrNull(
        ciphertextWithTag: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray? {
        requireKeyAndNonce(key, nonce)
        if (ciphertextWithTag.size < TAG_SIZE) return null
        return open(ciphertextWithTag, ad, nonce, key)
    }

    /** Verifies the tag, then decrypts; null when the tag does not verify. */
    private fun open(
        ciphertextWithTag: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray? {
        platformChaCha20Poly1305?.let { return it.open(ciphertextWithTag, ad, nonce, key) }
        return kotlinOpen(ciphertextWithTag, ad, nonce, key)
    }

    /** The Kotlin open, for sizes already checked and an input at least a tag long. */
    internal fun kotlinOpen(
        ciphertextWithTag: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray? {
        val ctLen = ciphertextWithTag.size - TAG_SIZE

        // Step 1: Generate Poly1305 one-time key
        val polyKey = ChaCha20Core.chaCha20PolyKey(key, nonce)

        // Step 2: Verify tag
        val expectedTag = computeTag(polyKey, ad, ciphertextWithTag, ctLen)
        polyKey.fill(0)
        val valid = expectedTag.equalsConstantTime(ciphertextWithTag.copyOfRange(ctLen, ciphertextWithTag.size))
        expectedTag.fill(0)
        if (!valid) return null

        // Step 3: Decrypt
        val plaintext = ByteArray(ctLen)
        ChaCha20Core.chaCha20XorInto(ciphertextWithTag, 0, ctLen, plaintext, 0, key, nonce, counter = 1)
        return plaintext
    }

    private fun requireKeyAndNonce(
        key: ByteArray,
        nonce: ByteArray,
    ) {
        require(key.size == KEY_SIZE) { "ChaCha20-Poly1305 key must be $KEY_SIZE bytes, was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "ChaCha20-Poly1305 nonce must be $NONCE_SIZE bytes, was ${nonce.size}" }
    }

    /**
     * Compute Poly1305 tag over the AEAD construction, streaming so nothing is copied:
     * pad16(ad) || pad16(ciphertext) || len(ad) as 8-byte LE || len(ct) as 8-byte LE,
     * where the ciphertext is the first [ctLen] bytes of [ciphertext].
     */
    private fun computeTag(
        polyKey: ByteArray,
        ad: ByteArray,
        ciphertext: ByteArray,
        ctLen: Int,
    ): ByteArray {
        val poly = Poly1305State(polyKey)
        poly.update(ad)
        poly.padToBlock()
        poly.update(ciphertext, 0, ctLen)
        poly.padToBlock()

        // Both lengths are non-negative Ints, so their high 4 bytes stay zero.
        val lengths = ByteArray(16)
        ad.size.intToLittleEndian(lengths, 0)
        ctLen.intToLittleEndian(lengths, 8)
        poly.update(lengths)
        return poly.finish()
    }
}

/**
 * A platform's ChaCha20-Poly1305, given sizes [ChaCha20Poly1305] has already checked and, for
 * [open], an input at least a tag long. [open] returns null exactly when the tag fails.
 */
internal interface ChaCha20Poly1305Backend {
    fun seal(
        plaintext: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray

    fun open(
        ciphertextWithTag: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray?
}

/** JCA's ChaCha20-Poly1305 on the JVM and Android when it has one; null runs the Kotlin one. */
internal expect val platformChaCha20Poly1305: ChaCha20Poly1305Backend?
