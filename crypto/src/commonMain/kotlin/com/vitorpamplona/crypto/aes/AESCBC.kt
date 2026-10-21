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

/** The name AES-CBC ciphers report from [SymmetricCipher.name]. */
const val AES_CBC_NAME = "aes-cbc"

/**
 * AES-CBC (NIST SP 800-38A) with PKCS#7 padding, under one key and one IV: the bytes of JCA's
 * "AES/CBC/PKCS5Padding". The block cipher is JCA on the JVM and Android, CommonCrypto on Apple
 * and a constant-time Kotlin AES on Linux; every platform pads, strips padding and checks
 * lengths with the same common code.
 *
 * **CBC is unauthenticated.** Anyone can change a ciphertext and [decrypt] will return altered
 * plaintext without noticing. Pair it with a MAC over the IV and ciphertext (encrypt-then-MAC)
 * and check the MAC before decrypting. Without one, any way an attacker can tell a padding
 * failure apart from other outcomes (the exception, a null, the timing) is a padding oracle that
 * lets them decrypt any message.
 *
 * The IV must be unpredictable and fresh for every message. Reusing one is less severe than
 * reusing a GCM nonce, but it shows which messages start with the same blocks. Unlike [AESGCM],
 * this class does not stop a second [encrypt].
 *
 * The key must be 16, 24 or 32 bytes and the IV 16, or the constructor throws
 * [IllegalArgumentException]. The instance takes what it needs from both arrays when it is
 * built, so changing them afterwards does not change it.
 *
 * [decrypt] throws [IllegalArgumentException] when the input is empty, is not a multiple of 16
 * bytes, or has bad padding, on every platform; [decryptOrNull] returns null in exactly those
 * cases.
 */
expect class AESCBC(
    keyBytes: ByteArray = RandomInstance.bytes(32),
    iv: ByteArray = RandomInstance.bytes(16),
) : SymmetricCipher {
    val keyBytes: ByteArray
    val iv: ByteArray

    override fun name(): String

    override fun encrypt(bytesToEncrypt: ByteArray): ByteArray

    override fun decrypt(bytesToDecrypt: ByteArray): ByteArray

    override fun decryptOrNull(bytesToDecrypt: ByteArray): ByteArray?
}
