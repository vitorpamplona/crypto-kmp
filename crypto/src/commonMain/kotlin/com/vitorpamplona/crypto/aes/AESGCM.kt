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

import com.vitorpamplona.crypto.SymmetricCipher
import com.vitorpamplona.crypto.random.RandomInstance

/** The name AES-GCM ciphers report from [SymmetricCipher.name]. */
const val AES_GCM_NAME = "aes-gcm"

/**
 * AES-GCM (NIST SP 800-38D) with a 128-bit tag, under one key and one nonce. The output of
 * [encrypt] is the ciphertext followed by the tag, the layout of JCA's "AES/GCM/NoPadding".
 * JCA on the JVM and Android; a constant-time Kotlin implementation on every native target.
 *
 * **One message per instance.** The nonce is fixed for the instance's life, and encrypting two
 * messages under the same key and nonce reveals the XOR of their plaintexts and lets anyone forge
 * tags. So the first [encrypt] (with or without AAD) uses the nonce up, and any later one throws
 * [IllegalStateException], even from another thread. Create a new instance, with a fresh nonce,
 * for every message. [decrypt] and [decryptOrNull] can be called any number of times.
 *
 * The default nonce is 16 random bytes rather than the 12 NIST recommends, because earlier
 * versions used 16 and data already sealed, or formats built on this class, depend on it. Any
 * non-empty length is valid: a nonce that is not 12 bytes is hashed into the initial counter
 * block (SP 800-38D §7.1), the same way in every GCM implementation, JCA's included. Pass a
 * 12-byte nonce for the standard length.
 *
 * The key must be 16, 24 or 32 bytes and the nonce non-empty, or the constructor throws
 * [IllegalArgumentException]. The instance takes what it needs from both arrays when it is
 * built, so changing them afterwards does not change it.
 *
 * [decrypt] throws [IllegalArgumentException] when the input is shorter than the tag or the tag
 * does not verify, on every platform; [decryptOrNull] returns null in exactly those cases.
 */
expect class AESGCM(
    keyBytes: ByteArray = RandomInstance.bytes(32),
    nonce: ByteArray = RandomInstance.bytes(16),
) : SymmetricCipher {
    val keyBytes: ByteArray
    val nonce: ByteArray

    override fun name(): String

    /** Throws [IllegalStateException] if this instance has already encrypted. */
    override fun encrypt(bytesToEncrypt: ByteArray): ByteArray

    override fun decrypt(bytesToDecrypt: ByteArray): ByteArray

    override fun decryptOrNull(bytesToDecrypt: ByteArray): ByteArray?

    /**
     * AES-GCM encrypt with Additional Authenticated Data (AAD). Throws [IllegalStateException]
     * if this instance has already encrypted.
     */
    fun encrypt(
        bytesToEncrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray

    /** AES-GCM decrypt with Additional Authenticated Data (AAD). */
    fun decrypt(
        bytesToDecrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray

    /** [decrypt] with AAD, returning null in exactly the cases where it would throw. */
    fun decryptOrNull(
        bytesToDecrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray?
}
