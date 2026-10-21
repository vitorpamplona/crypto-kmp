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
package com.vitorpamplona.crypto.mac

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
import platform.CoreCrypto.CCHmacAlgorithm
import platform.CoreCrypto.CCHmacContext
import platform.CoreCrypto.CCHmacFinal
import platform.CoreCrypto.CCHmacInit
import platform.CoreCrypto.CCHmacUpdate
import platform.CoreCrypto.kCCHmacAlgSHA1
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.CoreCrypto.kCCHmacAlgSHA512
import platform.posix.memset
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.Cleaner
import kotlin.native.ref.createCleaner

/**
 * The secrets a [MacInstance] holds: the keyed CCHmac context, and the key, kept because
 * CCHmacFinal consumes the keyed state and only CCHmacInit can re-arm it. A separate
 * object so the cleaner can wipe both without holding on to the [MacInstance].
 */
@OptIn(ExperimentalForeignApi::class)
private class HmacSecrets {
    val context: CPointer<CCHmacContext> = nativeHeap.alloc<CCHmacContext>().ptr
    var key: ByteArray = ByteArray(0)

    /** Wipes the key and the context and frees the context. Runs once, from the cleaner. */
    fun destroy() {
        key.fill(0)
        memset(context, 0, sizeOf<CCHmacContext>().convert())
        nativeHeap.free(context.rawValue)
    }
}

/** HMAC on CommonCrypto's CCHmac. Like JCA's `Mac`, [doFinal] leaves it keyed for the next message. */
@OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)
actual class MacInstance actual constructor(
    algorithm: String,
    key: ByteArray,
) {
    // Resolved before anything is allocated, so an unknown name throws with nothing to clean up.
    private var hmacAlgorithm: HmacAlgorithm = HmacAlgorithm.of(algorithm)
    private var ccAlgorithm: CCHmacAlgorithm = ccAlgorithmFor(hmacAlgorithm)

    // Native memory and the key: the cleaner wipes and frees them with this object.
    private val secrets = HmacSecrets()

    @Suppress("unused")
    private val cleaner: Cleaner = createCleaner(secrets) { it.destroy() }

    init {
        secrets.key = key.copyOf()
        rearm()
    }

    actual fun init(
        key: ByteArray,
        algorithm: String,
    ) {
        val requested = HmacAlgorithm.of(algorithm)
        hmacAlgorithm = requested
        ccAlgorithm = ccAlgorithmFor(requested)
        secrets.key.fill(0)
        secrets.key = key.copyOf()
        rearm()
    }

    actual fun getMacLength(): Int = hmacAlgorithm.macLength

    actual fun update(array: ByteArray) {
        if (array.isEmpty()) return
        array.usePinned { CCHmacUpdate(secrets.context, it.addressOf(0), array.size.convert()) }
    }

    actual fun update(byte: Byte) = update(byteArrayOf(byte))

    actual fun doFinal(): ByteArray = ByteArray(getMacLength()).also { doFinal(it, 0) }

    actual fun doFinal(
        output: ByteArray,
        offset: Int,
    ) {
        val macLength = getMacLength()
        require(offset >= 0 && macLength <= output.size - offset) { "no room for a $macLength-byte MAC" }
        output.usePinned { CCHmacFinal(secrets.context, it.addressOf(offset)) }
        rearm()
    }

    private fun rearm() {
        val key = secrets.key
        if (key.isEmpty()) {
            // addressOf(0) throws on an empty array; CCHmacInit takes null for a 0-byte key.
            CCHmacInit(secrets.context, ccAlgorithm, null, 0.convert())
        } else {
            key.usePinned { CCHmacInit(secrets.context, ccAlgorithm, it.addressOf(0), key.size.convert()) }
        }
    }

    private fun ccAlgorithmFor(algorithm: HmacAlgorithm): CCHmacAlgorithm =
        when (algorithm) {
            HmacAlgorithm.HMAC_SHA1 -> kCCHmacAlgSHA1
            HmacAlgorithm.HMAC_SHA256 -> kCCHmacAlgSHA256
            HmacAlgorithm.HMAC_SHA512 -> kCCHmacAlgSHA512
        }
}
