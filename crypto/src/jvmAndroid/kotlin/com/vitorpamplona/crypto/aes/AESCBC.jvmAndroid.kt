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
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-CBC on JCA's "AES/CBC/NoPadding", with the PKCS#7 padding added and checked by the common
 * [cbcEncrypt] and [cbcDecrypt], so padding errors and lengths behave as on every other platform.
 */
public actual class AESCBC actual constructor(
    public actual val keyBytes: ByteArray,
    public actual val iv: ByteArray,
) : SymmetricCipher {
    init {
        requireAesKey(keyBytes)
        requireCbcIv(iv)
    }

    // Both copy their arrays, so later changes to keyBytes or iv don't reach this instance.
    private val keySpec = SecretKeySpec(keyBytes, "AES")
    private val param = IvParameterSpec(iv)

    private fun crypt(
        mode: Int,
        blocks: ByteArray,
    ): ByteArray =
        try {
            with(Cipher.getInstance("AES/CBC/NoPadding")) {
                init(mode, keySpec, param)
                doFinal(blocks)
            }
        } catch (e: GeneralSecurityException) {
            throw IllegalArgumentException("AES-CBC failed", e)
        }

    actual override fun name(): String = AES_CBC_NAME

    actual override fun encrypt(bytesToEncrypt: ByteArray): ByteArray = cbcEncrypt(bytesToEncrypt) { crypt(Cipher.ENCRYPT_MODE, it) }

    actual override fun decrypt(bytesToDecrypt: ByteArray): ByteArray = cbcDecrypt(bytesToDecrypt) { crypt(Cipher.DECRYPT_MODE, it) }

    actual override fun decryptOrNull(bytesToDecrypt: ByteArray): ByteArray? =
        try {
            decrypt(bytesToDecrypt)
        } catch (_: IllegalArgumentException) {
            null
        }
}
