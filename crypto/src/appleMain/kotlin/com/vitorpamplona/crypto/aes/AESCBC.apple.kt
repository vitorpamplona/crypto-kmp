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
import com.vitorpamplona.crypto.nullOnDecryptFailure
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo
import kotlinx.cinterop.value
import platform.CoreCrypto.CCCrypt
import platform.CoreCrypto.CCOperation
import platform.CoreCrypto.kCCAlgorithmAES
import platform.CoreCrypto.kCCDecrypt
import platform.CoreCrypto.kCCEncrypt
import platform.CoreCrypto.kCCSuccess
import platform.posix.size_tVar

/**
 * AES-CBC on CommonCrypto's CCCrypt (hardware AES) without padding, with the PKCS#7 padding
 * added and checked by the common [cbcEncrypt] and [cbcDecrypt]: CCCrypt's own PKCS#7 check
 * accepts some invalid padding (a last byte above 16, for one), and its timing is unspecified.
 */
public actual class AESCBC actual constructor(
    public actual val keyBytes: ByteArray,
    public actual val iv: ByteArray,
) : SymmetricCipher {
    init {
        requireAesKey(keyBytes)
        requireCbcIv(iv)
    }

    // CCCrypt takes the raw key on every call: copies, so later changes to keyBytes or iv
    // don't reach this instance.
    private val key = keyBytes.copyOf()
    private val fixedIv = iv.copyOf()

    actual override fun name(): String = AES_CBC_NAME

    actual override fun encrypt(bytesToEncrypt: ByteArray): ByteArray = cbcEncrypt(bytesToEncrypt) { crypt(kCCEncrypt, it) }

    actual override fun decrypt(bytesToDecrypt: ByteArray): ByteArray = cbcDecrypt(bytesToDecrypt) { crypt(kCCDecrypt, it) }

    actual override fun decryptOrNull(bytesToDecrypt: ByteArray): ByteArray? = nullOnDecryptFailure { decrypt(bytesToDecrypt) }

    /** CBC without padding over [blocks], a non-empty whole number of 16-byte blocks. */
    @OptIn(ExperimentalForeignApi::class)
    private fun crypt(
        operation: CCOperation,
        blocks: ByteArray,
    ): ByteArray {
        val out = ByteArray(blocks.size)
        val written =
            memScoped {
                val moved = alloc<size_tVar>()
                val status =
                    CCCrypt(
                        operation,
                        kCCAlgorithmAES.convert(),
                        0u,
                        key.refTo(0),
                        key.size.convert(),
                        fixedIv.refTo(0),
                        blocks.refTo(0),
                        blocks.size.convert(),
                        out.refTo(0),
                        out.size.convert(),
                        moved.ptr,
                    )
                require(status == kCCSuccess) { "AES-CBC failed: CCCrypt status $status" }
                moved.value.toInt()
            }
        check(written == out.size) { "AES-CBC: CCCrypt wrote $written of ${out.size} bytes" }
        return out
    }
}
