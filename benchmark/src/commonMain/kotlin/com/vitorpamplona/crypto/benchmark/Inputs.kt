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
package com.vitorpamplona.crypto.benchmark

/**
 * The same inputs for every library: a 1 KiB and a 16 KiB message, 16 bytes of AAD, and
 * fixed keys, so each benchmark measures the operation and not the data it was given.
 */
object Inputs {
    val message1k = ByteArray(1024) { (it * 7).toByte() }
    val message16k = ByteArray(16 * 1024) { (it * 13).toByte() }
    val aad = ByteArray(16) { (0xA0 + it).toByte() }

    val aesKey = ByteArray(32) { (it + 1).toByte() }
    val chachaKey = ByteArray(32) { (it + 2).toByte() }
    val hmacKey = ByteArray(32) { (it + 3).toByte() }

    // RFC 7748 §6.1's Alice and Bob.
    val x25519Private = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    val x25519Public = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

    // RFC 8032 §7.1, test 1.
    val ed25519Seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
}

/** A 12-byte nonce that changes on every call: GCM implementations refuse a repeated one. */
class NonceCounter {
    private val nonce = ByteArray(12)
    private var counter = 0L

    fun next(): ByteArray {
        counter++
        for (i in 0 until 8) nonce[4 + i] = (counter ushr (8 * i)).toByte()
        return nonce
    }
}

private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
