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
package com.vitorpamplona.crypto.wycheproof

import com.vitorpamplona.crypto.aes.AESCBC
import com.vitorpamplona.crypto.aes.AESGCM
import com.vitorpamplona.crypto.chacha.ChaCha20Poly1305
import com.vitorpamplona.crypto.chacha.XChaCha20Poly1305
import com.vitorpamplona.crypto.curve25519.Ed25519
import com.vitorpamplona.crypto.curve25519.X25519
import com.vitorpamplona.crypto.ec.P256
import com.vitorpamplona.crypto.hexToByteArray
import com.vitorpamplona.crypto.kdf.Hkdf
import com.vitorpamplona.crypto.mac.MacInstance
import kotlin.test.Test
import kotlin.test.fail

/**
 * Project Wycheproof's vectors, on every platform: the edge cases (counter wraps, odd nonce
 * sizes, modified tags, bad padding, low-order and non-canonical points, malleable
 * signatures, empty salts, oversized outputs) that known-answer tests from the specs miss.
 *
 * "valid" vectors must give the expected bytes and "invalid" ones must be rejected, with an
 * [IllegalArgumentException] or a null from decryptOrNull. "acceptable" ones may go either
 * way, but when accepted they must give the expected bytes.
 */
class WycheproofTest {
    @Test
    fun aesGcm() =
        run(AES_GCM_VECTORS) { (key, iv, aad, msg, ct, tag) ->
            aead(
                encrypt = { AESGCM(key, iv).encrypt(msg, aad) },
                decrypt = { AESGCM(key, iv).decryptOrNull(ct + tag, aad) },
                msg = msg,
                sealed = ct + tag,
            )
        }

    @Test
    fun aesCbcPkcs5() =
        run(AES_CBC_PKCS5_VECTORS) { (key, iv, msg, ct) ->
            aead(
                encrypt = { AESCBC(key, iv).encrypt(msg) },
                decrypt = { AESCBC(key, iv).decryptOrNull(ct) },
                msg = msg,
                sealed = ct,
            )
        }

    @Test
    fun chaCha20Poly1305() =
        run(CHACHA20_POLY1305_VECTORS) { (key, iv, aad, msg, ct, tag) ->
            aead(
                encrypt = { ChaCha20Poly1305.encrypt(msg, aad, iv, key) },
                decrypt = { ChaCha20Poly1305.decryptOrNull(ct + tag, aad, iv, key) },
                msg = msg,
                sealed = ct + tag,
            )
        }

    @Test
    fun xChaCha20Poly1305() =
        run(XCHACHA20_POLY1305_VECTORS) { (key, iv, aad, msg, ct, tag) ->
            aead(
                encrypt = { XChaCha20Poly1305.encrypt(msg, aad, iv, key) },
                decrypt = { XChaCha20Poly1305.decryptOrNull(ct + tag, aad, iv, key) },
                msg = msg,
                sealed = ct + tag,
            )
        }

    @Test
    fun x25519() =
        run(X25519_VECTORS) { (public, private, shared) ->
            outcome(shared) { X25519.dh(private, public) }
        }

    /**
     * P-256 ECDH with uncompressed points, as TLS sends them. The private key is a big-endian
     * integer of any length here (a leading zero byte, or fewer bytes): normalized to 32.
     * Compressed points, which this API doesn't take, are "acceptable" or "invalid" in the file,
     * so rejecting them passes.
     */
    @Test
    fun ecdhP256() =
        run(ECDH_P256_VECTORS) { (public, private, shared) ->
            val scalar = private.dropWhile { it == 0.toByte() }.toByteArray()
            outcome(shared) { P256.dh(ByteArray(32 - scalar.size) + scalar, public) }
        }

    @Test
    fun ed25519() =
        run(ED25519_VECTORS) { (publicKey, msg, sig) ->
            if (Ed25519.verify(msg, sig, publicKey)) Outcome.Accepted else Outcome.Rejected
        }

    @Test
    fun hmacSha1() = hmac("HmacSHA1", HMAC_SHA1_VECTORS)

    @Test
    fun hmacSha256() = hmac("HmacSHA256", HMAC_SHA256_VECTORS)

    @Test
    fun hmacSha384() = hmac("HmacSHA384", HMAC_SHA384_VECTORS)

    @Test
    fun hmacSha512() = hmac("HmacSHA512", HMAC_SHA512_VECTORS)

    @Test
    fun hkdfSha1() = hkdf("HmacSHA1", HKDF_SHA1_VECTORS)

    @Test
    fun hkdfSha256() = hkdf("HmacSHA256", HKDF_SHA256_VECTORS)

    @Test
    fun hkdfSha384() = hkdf("HmacSHA384", HKDF_SHA384_VECTORS)

    @Test
    fun hkdfSha512() = hkdf("HmacSHA512", HKDF_SHA512_VECTORS)

    /** The tag is compared, truncated to the vector's tag size, as a verifier would. */
    private fun hmac(
        algorithm: String,
        vectors: Array<String>,
    ) = run(vectors, hexFrom = 1) { fields ->
        val tagBytes = fields.text(0).toInt() / 8
        val mac = MacInstance(algorithm, fields[1])
        mac.update(fields[2])
        if (mac.doFinal().copyOf(tagBytes).contentEquals(fields[3])) Outcome.Accepted else Outcome.Rejected
    }

    /** HKDF with an empty salt uses hashLen zero bytes (RFC 5869 §2.2), as JCA-free code must. */
    private fun hkdf(
        algorithm: String,
        vectors: Array<String>,
    ) = run(vectors, hexFrom = 0, textFields = setOf(3)) { fields ->
        val (ikm, salt, info) = fields
        val size = fields.text(3).toInt()
        outcome(fields[4]) {
            val hkdf = Hkdf(algorithm)
            hkdf.expand(hkdf.extract(ikm, salt), info, size)
        }
    }

    private enum class Outcome { Accepted, Rejected, WrongBytes }

    /** Accepted when [compute] gives [expected], Rejected when it throws IllegalArgumentException. */
    private fun outcome(
        expected: ByteArray,
        compute: () -> ByteArray,
    ): Outcome {
        val actual =
            try {
                compute()
            } catch (e: IllegalArgumentException) {
                return Outcome.Rejected
            }
        return if (actual.contentEquals(expected)) Outcome.Accepted else Outcome.WrongBytes
    }

    /**
     * An authenticated (or padded) cipher accepts a vector when encryption gives [sealed] and
     * decryption gives [msg] back, and rejects it when decryption refuses or a size is refused.
     * Anything in between (one direction working, or different bytes) is a failure.
     */
    private fun aead(
        encrypt: () -> ByteArray,
        decrypt: () -> ByteArray?,
        msg: ByteArray,
        sealed: ByteArray,
    ): Outcome {
        val opened =
            try {
                decrypt()
            } catch (e: IllegalArgumentException) {
                return Outcome.Rejected
            }
        if (opened == null) return Outcome.Rejected
        if (!opened.contentEquals(msg)) return Outcome.WrongBytes
        val encrypted =
            try {
                encrypt()
            } catch (e: IllegalArgumentException) {
                return Outcome.WrongBytes
            }
        return if (encrypted.contentEquals(sealed)) Outcome.Accepted else Outcome.WrongBytes
    }

    /** One vector's fields after tcId|result|flags, hex-decoded except [textFields]. */
    private class Fields(
        private val raw: List<String>,
        private val textFields: Set<Int>,
    ) {
        private val bytes = raw.mapIndexed { i, s -> if (i in textFields) ByteArray(0) else s.hexToByteArray() }

        operator fun get(index: Int): ByteArray = bytes[index]

        fun text(index: Int): String = raw[index]

        operator fun component1() = bytes[0]

        operator fun component2() = bytes[1]

        operator fun component3() = bytes[2]

        operator fun component4() = bytes[3]

        operator fun component5() = bytes[4]

        operator fun component6() = bytes[5]
    }

    /**
     * Runs every vector and fails once, listing each vector whose outcome breaks its result:
     * valid must be Accepted, invalid Rejected, acceptable either; WrongBytes always fails.
     * [hexFrom] fields before that index are text, like [textFields].
     */
    private fun run(
        vectors: Array<String>,
        hexFrom: Int = 0,
        textFields: Set<Int> = emptySet(),
        check: (Fields) -> Outcome,
    ) {
        val failures = mutableListOf<String>()
        for (vector in vectors) {
            val parts = vector.split('|')
            val (tcId, result, flags) = parts
            val fields = Fields(parts.drop(3), textFields + (0 until hexFrom))
            val outcome =
                try {
                    check(fields)
                } catch (e: Throwable) {
                    failures += "tcId $tcId ($result, $flags): threw $e"
                    continue
                }
            val ok =
                when (result) {
                    "valid" -> outcome == Outcome.Accepted
                    "invalid" -> outcome == Outcome.Rejected
                    "acceptable" -> outcome != Outcome.WrongBytes
                    else -> false
                }
            if (!ok) failures += "tcId $tcId ($result, $flags): $outcome"
        }
        if (failures.isNotEmpty()) fail("${failures.size} of ${vectors.size} vectors failed:\n" + failures.joinToString("\n"))
    }
}
