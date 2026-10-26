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

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.refTo
import kotlinx.cinterop.value
import platform.CoreCrypto.CCCrypt
import platform.CoreCrypto.CCCryptorCreateWithMode
import platform.CoreCrypto.CCCryptorRef
import platform.CoreCrypto.CCCryptorRefVar
import platform.CoreCrypto.CCCryptorRelease
import platform.CoreCrypto.CCCryptorUpdate
import platform.CoreCrypto.ccNoPadding
import platform.CoreCrypto.kCCAlgorithmAES
import platform.CoreCrypto.kCCEncrypt
import platform.CoreCrypto.kCCModeCTR
import platform.CoreCrypto.kCCModeOptionCTR_BE
import platform.CoreCrypto.kCCOptionECBMode
import platform.CoreCrypto.kCCSuccess
import platform.posix.size_tVar

/** GCM on CommonCrypto's AES (the CPU's AES instructions) and the Kotlin GHASH. */
internal actual fun gcmKey(key: ByteArray): GcmKey = CtrGcmKey(CommonCryptoAesCtr(key))

/**
 * AES through CommonCrypto: ECB for one block (the hash key H), CTR for keystreams. CommonCrypto
 * has no public GCM, but its CTR is the cipher half of one. It takes the raw key on every call,
 * so this keeps a copy, as AESCBC does.
 */
@OptIn(ExperimentalForeignApi::class)
internal class CommonCryptoAesCtr(
    key: ByteArray,
) : AesCtr {
    init {
        requireAesKey(key)
    }

    private val key = key.copyOf()

    override fun encryptBlock(block: ByteArray): ByteArray {
        val out = ByteArray(16)
        memScoped {
            val moved = alloc<size_tVar>()
            val status =
                CCCrypt(
                    kCCEncrypt,
                    kCCAlgorithmAES.convert(),
                    kCCOptionECBMode,
                    key.refTo(0),
                    key.size.convert(),
                    null,
                    block.refTo(0),
                    16.convert(),
                    out.refTo(0),
                    16.convert(),
                    moved.ptr,
                )
            check(status == kCCSuccess && moved.value.toInt() == 16) { "AES-ECB failed: CCCrypt status $status" }
        }
        return out
    }

    override fun stream(iv: ByteArray): AesCtrStream = Stream(iv)

    private inner class Stream(
        iv: ByteArray,
    ) : AesCtrStream {
        private val cryptor: CCCryptorRef =
            memScoped {
                val ref = alloc<CCCryptorRefVar>()
                val status =
                    CCCryptorCreateWithMode(
                        kCCEncrypt,
                        kCCModeCTR,
                        kCCAlgorithmAES.convert(),
                        ccNoPadding,
                        iv.refTo(0),
                        key.refTo(0),
                        key.size.convert(),
                        null,
                        0.convert(),
                        0,
                        kCCModeOptionCTR_BE,
                        ref.ptr,
                    )
                check(status == kCCSuccess) { "AES-CTR setup failed: CCCryptorCreateWithMode status $status" }
                checkNotNull(ref.value)
            }

        override fun xor(
            input: ByteArray,
            inputOffset: Int,
            length: Int,
            output: ByteArray,
            outputOffset: Int,
        ) {
            // refTo needs an element to point at; there is nothing to do for no bytes anyway.
            if (length == 0) return
            memScoped {
                val moved = alloc<size_tVar>()
                val status =
                    CCCryptorUpdate(
                        cryptor,
                        input.refTo(inputOffset),
                        length.convert(),
                        output.refTo(outputOffset),
                        length.convert(),
                        moved.ptr,
                    )
                check(status == kCCSuccess && moved.value.toInt() == length) { "AES-CTR failed: CCCryptorUpdate status $status" }
            }
        }

        override fun close() {
            CCCryptorRelease(cryptor)
        }
    }
}
