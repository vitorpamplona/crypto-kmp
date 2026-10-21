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
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

public actual class AESGCM actual constructor(
    public actual val keyBytes: ByteArray,
    public actual val nonce: ByteArray,
) : SymmetricCipher {
    init {
        requireAesKey(keyBytes)
        requireGcmNonce(nonce)
    }

    // Both copy their arrays, so later changes to keyBytes or nonce don't reach this instance.
    private val keySpec = SecretKeySpec(keyBytes, "AES")
    private val param = GCMParameterSpec(AesGcmKey.TAG_LENGTH * 8, nonce)

    private val guard = NonceGuard()

    private fun crypt(
        mode: Int,
        input: ByteArray,
        aad: ByteArray,
    ): ByteArray =
        with(Cipher.getInstance("AES/GCM/NoPadding")) {
            init(mode, keySpec, param)
            updateAAD(aad)
            doFinal(input)
        }

    actual override fun name(): String = AES_GCM_NAME

    actual override fun encrypt(bytesToEncrypt: ByteArray): ByteArray = encrypt(bytesToEncrypt, EMPTY)

    actual override fun decrypt(bytesToDecrypt: ByteArray): ByteArray = decrypt(bytesToDecrypt, EMPTY)

    actual override fun decryptOrNull(bytesToDecrypt: ByteArray): ByteArray? = decryptOrNull(bytesToDecrypt, EMPTY)

    public actual fun encrypt(
        bytesToEncrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        guard.claim()
        return crypt(Cipher.ENCRYPT_MODE, bytesToEncrypt, aad)
    }

    public actual fun decrypt(
        bytesToDecrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray =
        try {
            crypt(Cipher.DECRYPT_MODE, bytesToDecrypt, aad)
        } catch (e: GeneralSecurityException) {
            throw IllegalArgumentException("AES-GCM authentication failed", e)
        }

    public actual fun decryptOrNull(
        bytesToDecrypt: ByteArray,
        aad: ByteArray,
    ): ByteArray? =
        try {
            decrypt(bytesToDecrypt, aad)
        } catch (_: IllegalArgumentException) {
            null
        }

    private companion object {
        val EMPTY = ByteArray(0)
    }
}
