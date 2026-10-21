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
package com.vitorpamplona.crypto

/**
 * A symmetric cipher bound to one key and one nonce or IV, both fixed for the instance's life.
 *
 * Because the nonce is fixed, [encrypt] can be single-use: an implementation for which a reused
 * nonce is catastrophic, like [com.vitorpamplona.crypto.aes.AESGCM], throws
 * [IllegalStateException] on a second [encrypt]. Create one instance, with a fresh nonce, per
 * message. [decrypt] and [decryptOrNull] can always be called any number of times.
 */
public interface SymmetricCipher {
    /** A short name for the algorithm, such as `aes-gcm`. */
    public fun name(): String

    public fun encrypt(bytesToEncrypt: ByteArray): ByteArray

    /**
     * Throws [IllegalArgumentException] when [bytesToDecrypt] does not authenticate, has bad
     * padding, or has a length the cipher cannot have produced.
     */
    public fun decrypt(bytesToDecrypt: ByteArray): ByteArray

    /** [decrypt], returning null in exactly the cases where it would throw. */
    public fun decryptOrNull(bytesToDecrypt: ByteArray): ByteArray?
}

/**
 * Runs a decryption, mapping the failures every [SymmetricCipher.decrypt] reports with
 * [IllegalArgumentException] to null: the one shared body of every `decryptOrNull`.
 */
internal inline fun nullOnDecryptFailure(decryption: () -> ByteArray): ByteArray? =
    try {
        decryption()
    } catch (_: IllegalArgumentException) {
        null
    }
