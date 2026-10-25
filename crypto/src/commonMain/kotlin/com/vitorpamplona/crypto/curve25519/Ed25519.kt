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
package com.vitorpamplona.crypto.curve25519

import com.vitorpamplona.crypto.equalsConstantTime
import com.vitorpamplona.crypto.mul64
import com.vitorpamplona.crypto.random.RandomInstance

/*
 * The reduction mod L follows TweetNaCl by Daniel J. Bernstein, Bernard van
 * Gastel, Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers (public
 * domain). The point arithmetic, point decompression and both scalar
 * multiplications, in [Ed25519Group], follow ref10 by Daniel J. Bernstein,
 * Niels Duif, Tanja Lange, Peter Schwabe and Bo-Yin Yang (public domain), and
 * verification rejects what libsodium's does.
 */

/**
 * Ed25519 digital signatures (RFC 8032), in pure Kotlin over [Curve25519Field].
 *
 * Every platform runs this same code rather than a platform provider, whose
 * Ed25519 support varies across Android API levels. Key generation and signing
 * touch the secret scalar only through branch-free, mask-based selection;
 * being pure Kotlin they carry no hardware constant-time guarantee.
 * Verification handles only public data and runs in variable time.
 *
 * Private key format: 32-byte seed + 32-byte public key (64 bytes total). Only
 * the seed is used: [sign] and [publicFromPrivate] derive the public key from
 * it rather than trusting the stored copy.
 * Public key format: 32-byte compressed Edwards point.
 */
public object Ed25519 {
    private const val SEED_LENGTH = 32
    private const val PUBLIC_KEY_LENGTH = 32

    /**
     * Generate a new Ed25519 key pair.
     * @return pair of (privateKey: 64 bytes seed+public, publicKey: 32 bytes)
     */
    public fun generateKeyPair(): Ed25519KeyPair {
        val seed = RandomInstance.bytes(SEED_LENGTH)
        val publicKey = derivePublicKey(seed)
        val privateKey = seed + publicKey
        seed.fill(0)
        return Ed25519KeyPair(privateKey, publicKey)
    }

    /**
     * Sign a message using Ed25519.
     * @param message the data to sign
     * @param privateKey 64-byte private key (seed + public key)
     * @return 64-byte Ed25519 signature
     */
    public fun sign(
        message: ByteArray,
        privateKey: ByteArray,
    ): ByteArray {
        require(privateKey.size == SEED_LENGTH * 2) { "Private key must be 64 bytes (seed + public)" }

        val seed = privateKey.copyOfRange(0, SEED_LENGTH)
        // SHA-512(seed), clamped: the secret scalar a, then the nonce prefix.
        val expanded = expandSeed(seed)
        val scalar = expanded.copyOfRange(0, 32)
        val prefix = expanded.copyOfRange(32, 64)

        // A is derived from the seed, never read from privateKey[32..64]. A
        // tampered second half would go into the challenge below, and two
        // signatures of one message under seed||A and seed||A' share r but not
        // the challenge: two equations, enough to solve for a.
        val point = GeP3()
        Ed25519Group.scalarMultBase(point, scalar)
        val publicKey = Ed25519Group.encode(point)

        // r = SHA-512(prefix || message) mod L
        val rHash = sha512(prefix, message)
        val r = reduce(rHash)

        // R = [r]B
        Ed25519Group.scalarMultBase(point, r)
        val rBytes = Ed25519Group.encode(point)
        point.wipe()

        // S = (r + SHA-512(R || A || message) * a) mod L
        val hram = reduce(sha512(rBytes, publicKey, message))

        val signature = ByteArray(64)
        rBytes.copyInto(signature, 0)

        // Compute S = r + hram * a (mod L) in 64-byte arithmetic
        val x = LongArray(64)
        for (i in 0 until 32) x[i] = (r[i].toInt() and 0xFF).toLong()
        for (i in 0 until 32) {
            for (j in 0 until 32) {
                x[i + j] += ((hram[i].toInt() and 0xFF) * (scalar[j].toInt() and 0xFF)).toLong()
            }
        }

        val sBytes = modL(x)
        sBytes.copyInto(signature, 32)

        seed.fill(0)
        expanded.fill(0)
        scalar.fill(0)
        prefix.fill(0)
        rHash.fill(0)
        r.fill(0)
        return signature
    }

    /**
     * Verify an Ed25519 signature.
     *
     * Beyond the cofactorless RFC 8032 equation [S]B = R + [k]A, this rejects
     * what libsodium rejects:
     * - S must be below L, so S + L is not a second valid signature;
     * - A and R must be canonical encodings: y below p, and no sign bit on x = 0;
     * - A and R must not have small order, where [8]P is the identity. A
     *   small-order key verifies some signatures for any message.
     *
     * @param message the signed data
     * @param signature 64-byte signature
     * @param publicKey 32-byte public key
     * @return true if signature is valid; false for anything else, including a
     *   signature or public key of the wrong length.
     */
    public fun verify(
        message: ByteArray,
        signature: ByteArray,
        publicKey: ByteArray,
    ): Boolean {
        if (publicKey.size != PUBLIC_KEY_LENGTH || signature.size != 64) return false

        val rBytes = signature.copyOfRange(0, 32)
        val sBytes = signature.copyOfRange(32, 64)

        // Check s < L
        if (!isCanonicalScalar(sBytes)) return false

        val aPoint = Ed25519Group.decodeVartime(publicKey) ?: return false
        if (Ed25519Group.hasSmallOrder(aPoint)) return false
        // R is compared as bytes at the end, which already rules out a
        // non-canonical R; decoding it here also rules out a small-order one.
        val rPoint = Ed25519Group.decodeVartime(rBytes) ?: return false
        if (Ed25519Group.hasSmallOrder(rPoint)) return false

        val hram = reduce(sha512(rBytes, publicKey, message))

        // [S]B = R + [hram]A holds exactly when [hram](-A) + [S]B encodes to R.
        // Both multiplications happen in one variable-time pass, which is safe
        // because A, hram, S and R are all public: nothing here is a secret.
        Ed25519Group.negate(aPoint)
        val rCheck = GeP2()
        Ed25519Group.doubleScalarMultVartime(rCheck, hram, aPoint, sBytes)

        return Ed25519Group.encode(rCheck).contentEquals(rBytes)
    }

    /**
     * Derive the public key from a private key.
     *
     * The key is computed from the seed, the first 32 bytes. The copy stored in
     * the second half is ignored, as [sign] ignores it.
     *
     * @param privateKey 64-byte private key (seed + public key)
     * @return 32-byte public key
     */
    public fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        require(privateKey.size == SEED_LENGTH * 2) { "Private key must be 64 bytes (seed + public)" }
        val seed = privateKey.copyOfRange(0, SEED_LENGTH)
        val publicKey = derivePublicKey(seed)
        seed.fill(0)
        return publicKey
    }

    /**
     * Rebuilds a key pair from its 32-byte seed.
     *
     * [generateKeyPair] makes a fresh random one, which is right for a real
     * client and useless for anything that has to reproduce a specific key:
     * an interop fixture generated by another implementation, a test vector, or
     * a private key stored in another layout (PKCS#8 keeps only the seed, so the
     * seed is all you get back out).
     *
     * @param seed exactly 32 bytes. The public half is derived, never supplied,
     *   so a mismatched pair cannot be constructed here.
     */
    public fun keyPairFromSeed(seed: ByteArray): Ed25519KeyPair {
        require(seed.size == SEED_LENGTH) { "Ed25519 seed must be $SEED_LENGTH bytes, was ${seed.size}" }
        val publicKey = derivePublicKey(seed)
        return Ed25519KeyPair(seed + publicKey, publicKey)
    }

    // --- Internal operations ---

    /** SHA-512 of the seed, its first half clamped into the secret scalar (RFC 8032 §5.1.5). */
    private fun expandSeed(seed: ByteArray): ByteArray {
        val h = sha512(seed)
        h[0] = (h[0].toInt() and 248).toByte()
        h[31] = ((h[31].toInt() and 63) or 64).toByte()
        return h
    }

    /** Derive Ed25519 public key from 32-byte seed. */
    private fun derivePublicKey(seed: ByteArray): ByteArray {
        val expanded = expandSeed(seed)
        val scalar = expanded.copyOfRange(0, 32)
        val point = GeP3()
        Ed25519Group.scalarMultBase(point, scalar)
        val publicKey = Ed25519Group.encode(point)
        point.wipe()
        expanded.fill(0)
        scalar.fill(0)
        return publicKey
    }

    private fun sha512(vararg parts: ByteArray): ByteArray = ed25519Sha512(*parts)

    // --- Scalar reduction modulo L ---
    // L = 2^252 + 27742317777372353535851937790883648493

    private val L =
        longArrayOf(
            0xED,
            0xD3,
            0xF5,
            0x5C,
            0x1A,
            0x63,
            0x12,
            0x58,
            0xD6,
            0x9C,
            0xF7,
            0xA2,
            0xDE,
            0xF9,
            0xDE,
            0x14,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x10,
        )

    /**
     * Reduce a 64-byte hash to a 32-byte scalar modulo L.
     * This is used for Ed25519 nonce and challenge computation.
     */
    private fun reduce(input: ByteArray): ByteArray {
        val x = LongArray(64)
        for (i in 0 until 64) x[i] = (input[i].toInt() and 0xFF).toLong()
        return modL(x)
    }

    /**
     * Reduce a 64-element long array modulo L, returning a 32-byte result.
     * Consumes [x]: it is left zeroed, since it can hold a secret nonce.
     */
    private fun modL(x: LongArray): ByteArray {
        for (i in 63 downTo 32) {
            var carry: Long = 0
            var j = i - 32
            val k = i - 12
            while (j < k) {
                x[j] += carry - mul64(x[i] shl 4, L[j - (i - 32)])
                carry = (x[j] + 128) shr 8
                x[j] -= carry shl 8
                j++
            }
            x[j] += carry
            x[i] = 0
        }

        var carry: Long = 0
        for (j in 0 until 32) {
            x[j] += carry - mul64(x[31] shr 4, L[j])
            carry = x[j] shr 8
            x[j] = x[j] and 0xFF
        }
        for (j in 0 until 32) {
            x[j] -= mul64(carry, L[j])
        }

        val r = ByteArray(32)
        for (i in 0 until 32) {
            x[i + 1] += x[i] shr 8
            r[i] = (x[i] and 0xFF).toByte()
        }
        x.fill(0)
        return r
    }

    /**
     * Check if a scalar s < L (canonical). Compares from the high byte down and
     * stops at the first difference, which is fine: S is public.
     */
    private fun isCanonicalScalar(s: ByteArray): Boolean {
        for (i in 31 downTo 0) {
            val si = (s[i].toInt() and 0xFF).toLong()
            if (si < L[i]) return true
            if (si > L[i]) return false
        }
        return false // s == L is not canonical
    }
}

/**
 * An Ed25519 key pair: [privateKey] is the 32-byte seed followed by the 32-byte
 * [publicKey].
 *
 * Equality and hash code go by the key bytes, not by array identity; the
 * private keys are compared in constant time. [toString] prints no key bytes,
 * so a pair that ends up in a log or an exception message leaks nothing.
 */
public data class Ed25519KeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Ed25519KeyPair) return false
        return privateKey.equalsConstantTime(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }

    override fun toString(): String = "Ed25519KeyPair(privateKey=<${privateKey.size} bytes>, publicKey=<${publicKey.size} bytes>)"
}
