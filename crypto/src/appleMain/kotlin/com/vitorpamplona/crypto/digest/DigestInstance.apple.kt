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
package com.vitorpamplona.crypto.digest

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.rawValue
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA1_CTX
import platform.CoreCrypto.CC_SHA1_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA1_Final
import platform.CoreCrypto.CC_SHA1_Init
import platform.CoreCrypto.CC_SHA1_Update
import platform.CoreCrypto.CC_SHA256_CTX
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA256_Final
import platform.CoreCrypto.CC_SHA256_Init
import platform.CoreCrypto.CC_SHA256_Update
import platform.CoreCrypto.CC_SHA384_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA384_Final
import platform.CoreCrypto.CC_SHA384_Init
import platform.CoreCrypto.CC_SHA384_Update
import platform.CoreCrypto.CC_SHA512_CTX
import platform.CoreCrypto.CC_SHA512_DIGEST_LENGTH
import platform.CoreCrypto.CC_SHA512_Final
import platform.CoreCrypto.CC_SHA512_Init
import platform.CoreCrypto.CC_SHA512_Update
import platform.posix.memcpy
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.Cleaner
import kotlin.native.ref.createCleaner

/**
 * SHA-1 and SHA-2 on CommonCrypto (hardware-accelerated); RIPEMD-160 in Kotlin. A CommonCrypto
 * context is a plain struct, so [copy] copies its bytes into a new one.
 */
@OptIn(ExperimentalForeignApi::class)
public actual class DigestInstance private constructor(
    private val digest: StreamingDigest,
) {
    public actual constructor(algorithm: String) : this(
        when (val known = DigestAlgorithm.of(algorithm)) {
            DigestAlgorithm.SHA_256 -> CommonCryptoSha256()
            DigestAlgorithm.SHA_1 -> CommonCryptoSha1()
            DigestAlgorithm.SHA_384 -> CommonCryptoSha384()
            DigestAlgorithm.SHA_512 -> CommonCryptoSha512()
            DigestAlgorithm.RIPEMD_160 -> kotlinStreamingDigest(known)
        },
    )

    public actual fun update(array: ByteArray): Unit = digest.update(array)

    public actual fun update(byte: Byte): Unit = digest.update(byte)

    public actual fun digest(): ByteArray = digest.digest()

    public actual fun digest(input: ByteArray): ByteArray {
        digest.update(input)
        return digest.digest()
    }

    public actual fun copy(): DigestInstance = DigestInstance(digest.copy())
}

@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
private class CommonCryptoSha256(
    from: CPointer<CC_SHA256_CTX>? = null,
) : StreamingDigest {
    // The context lives on the native heap; the cleaner frees it with this object.
    private val context: CPointer<CC_SHA256_CTX> = nativeHeap.alloc<CC_SHA256_CTX>().ptr

    @Suppress("unused")
    private val cleaner: Cleaner = createCleaner(context) { nativeHeap.free(it.rawValue) }

    init {
        if (from == null) CC_SHA256_Init(context) else memcpy(context, from, sizeOf<CC_SHA256_CTX>().convert())
    }

    override fun update(array: ByteArray) {
        if (array.isEmpty()) return
        array.usePinned { CC_SHA256_Update(context, it.addressOf(0), array.size.convert()) }
    }

    override fun update(byte: Byte) = update(byteArrayOf(byte))

    override fun digest(): ByteArray {
        val out = UByteArray(CC_SHA256_DIGEST_LENGTH)
        out.usePinned { CC_SHA256_Final(it.addressOf(0), context) }
        CC_SHA256_Init(context)
        return out.toByteArray()
    }

    override fun copy(): StreamingDigest = CommonCryptoSha256(context)
}

@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
private class CommonCryptoSha1(
    from: CPointer<CC_SHA1_CTX>? = null,
) : StreamingDigest {
    private val context: CPointer<CC_SHA1_CTX> = nativeHeap.alloc<CC_SHA1_CTX>().ptr

    @Suppress("unused")
    private val cleaner: Cleaner = createCleaner(context) { nativeHeap.free(it.rawValue) }

    init {
        if (from == null) CC_SHA1_Init(context) else memcpy(context, from, sizeOf<CC_SHA1_CTX>().convert())
    }

    override fun update(array: ByteArray) {
        if (array.isEmpty()) return
        array.usePinned { CC_SHA1_Update(context, it.addressOf(0), array.size.convert()) }
    }

    override fun update(byte: Byte) = update(byteArrayOf(byte))

    override fun digest(): ByteArray {
        val out = UByteArray(CC_SHA1_DIGEST_LENGTH)
        out.usePinned { CC_SHA1_Final(it.addressOf(0), context) }
        CC_SHA1_Init(context)
        return out.toByteArray()
    }

    override fun copy(): StreamingDigest = CommonCryptoSha1(context)
}

@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
private class CommonCryptoSha512(
    from: CPointer<CC_SHA512_CTX>? = null,
) : StreamingDigest {
    private val context: CPointer<CC_SHA512_CTX> = nativeHeap.alloc<CC_SHA512_CTX>().ptr

    @Suppress("unused")
    private val cleaner: Cleaner = createCleaner(context) { nativeHeap.free(it.rawValue) }

    init {
        if (from == null) CC_SHA512_Init(context) else memcpy(context, from, sizeOf<CC_SHA512_CTX>().convert())
    }

    override fun update(array: ByteArray) {
        if (array.isEmpty()) return
        array.usePinned { CC_SHA512_Update(context, it.addressOf(0), array.size.convert()) }
    }

    override fun update(byte: Byte) = update(byteArrayOf(byte))

    override fun digest(): ByteArray {
        val out = UByteArray(CC_SHA512_DIGEST_LENGTH)
        out.usePinned { CC_SHA512_Final(it.addressOf(0), context) }
        CC_SHA512_Init(context)
        return out.toByteArray()
    }

    override fun copy(): StreamingDigest = CommonCryptoSha512(context)
}

/** SHA-384 runs on CommonCrypto's SHA-512 context, from SHA-384's initial values. */
@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
private class CommonCryptoSha384(
    from: CPointer<CC_SHA512_CTX>? = null,
) : StreamingDigest {
    private val context: CPointer<CC_SHA512_CTX> = nativeHeap.alloc<CC_SHA512_CTX>().ptr

    @Suppress("unused")
    private val cleaner: Cleaner = createCleaner(context) { nativeHeap.free(it.rawValue) }

    init {
        if (from == null) CC_SHA384_Init(context) else memcpy(context, from, sizeOf<CC_SHA512_CTX>().convert())
    }

    override fun update(array: ByteArray) {
        if (array.isEmpty()) return
        array.usePinned { CC_SHA384_Update(context, it.addressOf(0), array.size.convert()) }
    }

    override fun update(byte: Byte) = update(byteArrayOf(byte))

    override fun digest(): ByteArray {
        val out = UByteArray(CC_SHA384_DIGEST_LENGTH)
        out.usePinned { CC_SHA384_Final(it.addressOf(0), context) }
        CC_SHA384_Init(context)
        return out.toByteArray()
    }

    override fun copy(): StreamingDigest = CommonCryptoSha384(context)
}
