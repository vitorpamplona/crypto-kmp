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
package com.vitorpamplona.crypto.ec

import com.vitorpamplona.crypto.equalsConstantTime
import com.vitorpamplona.crypto.random.RandomInstance

/**
 * P-256 (secp256r1, NIST P-256) Diffie-Hellman: ECDH as TLS 1.3 uses it (RFC 8446 §4.2.8.2,
 * §7.4.2).
 *
 * Keys are encoded as TLS sends them: a private key is a 32-byte big-endian scalar in
 * [1, n-1], and a public key the 65-byte uncompressed SEC1 point 0x04 ‖ X ‖ Y. [dh] returns
 * the 32-byte big-endian x-coordinate of the shared point.
 *
 * Every platform runs the same pure-Kotlin code: [P256Field]'s Montgomery arithmetic and
 * [P256Point]'s complete addition formulas, with a fixed-window scalar multiplication. None
 * of it branches on or indexes by the private scalar, but, being pure Kotlin, it carries no
 * hardware constant-time guarantee.
 *
 * Every failure throws [IllegalArgumentException]: a key of the wrong size, a private scalar
 * outside [1, n-1], and a peer point that is not uncompressed, has a coordinate at or above p,
 * or is not on the curve. That covers RFC 8446 §4.2.8.2's checks; the point at infinity has no
 * 65-byte encoding, and a valid point times a valid scalar never reaches it, since the group
 * has prime order n. Compressed points are not supported.
 */
public object P256 {
    /** Size of a private key: a big-endian scalar. */
    public const val PRIVATE_KEY_LENGTH: Int = 32

    /** Size of a public key: 0x04 ‖ X ‖ Y. */
    public const val PUBLIC_KEY_LENGTH: Int = 65

    /** Size of a shared secret: the x-coordinate. */
    public const val SHARED_SECRET_LENGTH: Int = 32

    /** n, the order of the group G generates (SEC 2 §2.4.2), big-endian. */
    private val ORDER = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

    /**
     * A new key pair: a private scalar drawn uniformly from [1, n-1] by [RandomInstance], by
     * rejection (a 32-byte draw falls outside about once in 2^32), and its public key.
     */
    public fun generateKeyPair(): P256KeyPair {
        while (true) {
            val privateKey = RandomInstance.bytes(PRIVATE_KEY_LENGTH)
            if (isValidScalar(privateKey)) return P256KeyPair(privateKey, publicFromPrivate(privateKey))
            privateKey.fill(0)
        }
    }

    /**
     * The public key of [privateKey]: [privateKey]·G as an uncompressed SEC1 point.
     *
     * @param privateKey 32-byte big-endian scalar in [1, n-1]
     * @return 65-byte public key, 0x04 ‖ X ‖ Y
     * @throws IllegalArgumentException if [privateKey] is not 32 bytes or not in [1, n-1]
     */
    public fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        requireScalar(privateKey)
        val point = P256Point.scalarMult(privateKey, P256Point.generator())
        val out = ByteArray(PUBLIC_KEY_LENGTH)
        out[0] = 0x04
        toAffine(point, out, 1, withY = true)
        point.wipe()
        return out
    }

    /**
     * ECDH: the x-coordinate of [privateKey]·[peerPublicKey] (RFC 8446 §7.4.2).
     *
     * [peerPublicKey] is checked before it is used (RFC 8446 §4.2.8.2): 65 bytes, a leading
     * 0x04, both coordinates below p, and on the curve.
     *
     * @param privateKey 32-byte big-endian scalar in [1, n-1]
     * @param peerPublicKey the peer's 65-byte uncompressed point, 0x04 ‖ X ‖ Y
     * @return 32-byte shared secret, big-endian
     * @throws IllegalArgumentException if [privateKey] is not a valid scalar or
     *   [peerPublicKey] is not a valid point
     */
    public fun dh(
        privateKey: ByteArray,
        peerPublicKey: ByteArray,
    ): ByteArray {
        requireScalar(privateKey)
        val peer = decodePoint(peerPublicKey)
        val shared = P256Point.scalarMult(privateKey, peer)
        // Unreachable for a valid scalar and point (prime order), checked all the same.
        require(P256Field.isZero(shared.z) == 0) { "P-256 shared point is the point at infinity" }
        val out = ByteArray(SHARED_SECRET_LENGTH)
        toAffine(shared, out, 0, withY = false)
        shared.wipe()
        return out
    }

    private fun requireScalar(privateKey: ByteArray) {
        require(privateKey.size == PRIVATE_KEY_LENGTH) { "P-256 private key must be $PRIVATE_KEY_LENGTH bytes, was ${privateKey.size}" }
        require(isValidScalar(privateKey)) { "P-256 private key must be in [1, n-1]" }
    }

    /**
     * Whether the 32-byte big-endian [k] is in [1, n-1]: k - n borrows, and k is not zero.
     * Computed over every byte, so the time says nothing about where k and n differ.
     */
    private fun isValidScalar(k: ByteArray): Boolean {
        var borrow = 0
        var any = 0
        for (i in PRIVATE_KEY_LENGTH - 1 downTo 0) {
            val ki = k[i].toInt() and 0xFF
            borrow = ((ki - (ORDER[i].toInt() and 0xFF) - borrow) ushr 31) and 1
            any = any or ki
        }
        return (borrow and ((any or -any) ushr 31)) == 1
    }

    /** The point [encoded] holds, after RFC 8446 §4.2.8.2's checks; public data, so they may branch. */
    private fun decodePoint(encoded: ByteArray): P256Point {
        require(encoded.size == PUBLIC_KEY_LENGTH) { "P-256 public key must be $PUBLIC_KEY_LENGTH bytes, was ${encoded.size}" }
        require(encoded[0] == 0x04.toByte()) { "P-256 public key must be an uncompressed point (0x04)" }
        require(belowP(encoded, 1) && belowP(encoded, 33)) { "P-256 public key has a coordinate at or above p" }
        val x = P256Field.fromBytes(encoded, 1)
        val y = P256Field.fromBytes(encoded, 33)
        P256Field.toMontgomery(x, x)
        P256Field.toMontgomery(y, y)
        require(P256Point.isOnCurve(x, y)) { "P-256 public key is not on the curve" }
        return P256Point(x, y, P256Field.ONE.copyOf())
    }

    /** Whether the 32 big-endian bytes at [offset] are below p. */
    private fun belowP(
        bytes: ByteArray,
        offset: Int,
    ): Boolean {
        for (i in 0 until 32) {
            val a = bytes[offset + i].toInt() and 0xFF
            val b = P256Field.P_BYTES[i].toInt() and 0xFF
            if (a != b) return a < b
        }
        return false
    }

    /** Writes x (and y, if [withY]) of the affine form of [point] into [out] at [offset]. */
    private fun toAffine(
        point: P256Point,
        out: ByteArray,
        offset: Int,
        withY: Boolean,
    ) {
        val zInverse = P256Field.zero()
        val coordinate = P256Field.zero()
        P256Field.invert(zInverse, point.z)
        P256Field.mul(coordinate, point.x, zInverse)
        P256Field.fromMontgomery(coordinate, coordinate)
        P256Field.toBytes(coordinate, out, offset)
        if (withY) {
            P256Field.mul(coordinate, point.y, zInverse)
            P256Field.fromMontgomery(coordinate, coordinate)
            P256Field.toBytes(coordinate, out, offset + 32)
        }
        zInverse.fill(0)
        coordinate.fill(0)
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

/**
 * A P-256 key pair: a 32-byte big-endian [privateKey] scalar and its 65-byte uncompressed
 * [publicKey], 0x04 ‖ X ‖ Y.
 *
 * Equality and hash code go by the key bytes, not by array identity; the private keys are
 * compared in constant time. [toString] prints no key bytes, so a pair that ends up in a log or
 * an exception message leaks nothing.
 */
public data class P256KeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is P256KeyPair) return false
        return privateKey.equalsConstantTime(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }

    override fun toString(): String = "P256KeyPair(privateKey=<${privateKey.size} bytes>, publicKey=<${publicKey.size} bytes>)"
}
