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

import java.security.NoSuchAlgorithmException
import javax.crypto.Mac

/** HMAC on JCA's `Mac`. */
public actual class MacInstance actual constructor(
    algorithm: String,
    key: ByteArray,
) {
    private var algorithm = HmacAlgorithm.of(algorithm)
    private var mac: Mac = newMac(this.algorithm, key)

    public actual fun init(
        key: ByteArray,
        algorithm: String,
    ) {
        val requested = HmacAlgorithm.of(algorithm)
        // A JCA Mac keeps the algorithm it was made with whatever the key says, so a
        // different algorithm needs a new one.
        if (requested == this.algorithm) {
            mac.init(FixedKey(key, requested.jcaName))
        } else {
            mac = newMac(requested, key)
            this.algorithm = requested
        }
    }

    public actual fun getMacLength(): Int = mac.macLength

    public actual fun update(array: ByteArray): Unit = mac.update(array)

    public actual fun update(byte: Byte): Unit = mac.update(byte)

    public actual fun doFinal(): ByteArray = mac.doFinal()

    public actual fun doFinal(
        output: ByteArray,
        offset: Int,
    ) {
        // JCA would throw ShortBufferException; checked here to throw what the other platforms do.
        val macLength = mac.macLength
        require(offset >= 0 && macLength <= output.size - offset) { "no room for a $macLength-byte MAC" }
        mac.doFinal(output, offset)
    }

    private fun newMac(
        algorithm: HmacAlgorithm,
        key: ByteArray,
    ): Mac {
        val mac =
            try {
                Mac.getInstance(algorithm.jcaName)
            } catch (e: NoSuchAlgorithmException) {
                throw IllegalArgumentException("Unsupported MAC algorithm: ${algorithm.jcaName}", e)
            }
        mac.init(FixedKey(key, algorithm.jcaName))
        return mac
    }
}
