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
 * Pure Kotlin implementation of XChaCha20-Poly1305 AEAD (RFC 8439 §2.8 + XChaCha20 draft).
 *
 * All functions are stateless and thread-safe.
 *
 * Construction (draft-irtf-cfrg-xchacha §2.3):
 * 1. Derive subkey via HChaCha20(key, nonce[0..15])
 * 2. Build 12-byte subnonce: 0x00000000 || nonce[16..23]
 * 3. [ChaCha20Poly1305] with the subkey and subnonce
 *
 * Sizes and failures are handled as in [ChaCha20Poly1305], with a 24-byte nonce.
 */
public object XChaCha20Poly1305 {
    /**
     * AEAD encrypt.
     *
     * @param plaintext message to encrypt
     * @param ad associated data (authenticated but not encrypted)
     * @param nonce 24-byte nonce
     * @param key 32-byte key
     * @return ciphertext || 16-byte tag
     */
    public fun encrypt(
        plaintext: ByteArray,
        ad: ByteArray,
        nonce: ByteArray,
        key: ByteArray,
    ): ByteArray {
        val subKey = ChaCha20Core.xChaCha20SubKey(key, nonce)
        try {
            return ChaCha20Poly1305.encrypt(plaintext, ad, ChaCha20Core.xChaCha20SubNonce(nonce), subKey)
        } finally {
            subKey.fill(0)
        }
    }

    /**
     * AEAD decrypt.
     *
     * @param ciphertextWithTag ciphertext || 16-byte tag
     * @param ad associated data
     * @param nonce 24-byte nonce
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
        val subKey = ChaCha20Core.xChaCha20SubKey(key, nonce)
        try {
            return ChaCha20Poly1305.decrypt(ciphertextWithTag, ad, ChaCha20Core.xChaCha20SubNonce(nonce), subKey)
        } finally {
            subKey.fill(0)
        }
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
        val subKey = ChaCha20Core.xChaCha20SubKey(key, nonce)
        try {
            return ChaCha20Poly1305.decryptOrNull(ciphertextWithTag, ad, ChaCha20Core.xChaCha20SubNonce(nonce), subKey)
        } finally {
            subKey.fill(0)
        }
    }
}
