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
package com.vitorpamplona.crypto.benchmark.android

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Android's own JCA: AndroidOpenSSL (BoringSSL in C) for nearly everything, which is what an app
 * gets without a library. ChaCha20-Poly1305 needs API 28, X25519 and Ed25519 newer still; where
 * the device lacks one, that operation returns null and its benchmark is skipped.
 */
class AndroidJcaOperations : Operations {
    private val nonces = NonceCounter()
    private val aesKey = SecretKeySpec(Inputs.aesKey, "AES")
    private val chachaKey = SecretKeySpec(Inputs.chachaKey, "ChaCha20")
    private val hmacKey = SecretKeySpec(Inputs.hmacKey, "HmacSHA256")

    // Keys from their DER encodings, which every provider parses: RFC 8410's PKCS#8 and X.509.
    private val x25519Private: PrivateKey? = orNull { KeyFactory.getInstance("XDH").generatePrivate(PKCS8EncodedKeySpec(der(X25519_PKCS8, Inputs.x25519Private))) }
    private val x25519Public: PublicKey? = orNull { KeyFactory.getInstance("XDH").generatePublic(X509EncodedKeySpec(der(X25519_X509, Inputs.x25519Public))) }
    private val ed25519Private: PrivateKey? = orNull { KeyFactory.getInstance("Ed25519").generatePrivate(PKCS8EncodedKeySpec(der(ED25519_PKCS8, Inputs.ed25519Seed))) }
    private val ed25519Public: PublicKey? = orNull { KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der(ED25519_X509, Inputs.ed25519Public))) }
    private val ed25519Signature: ByteArray? = ed25519Sign()

    // P-256 has been in Android's JCA all along: keys from the curve's named parameters.
    private val p256 = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
    private val p256Private: PrivateKey = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, Inputs.p256Private), p256))
    private val p256Public: PublicKey =
        KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(ECPoint(BigInteger(1, Inputs.p256Public.copyOfRange(1, 33)), BigInteger(1, Inputs.p256Public.copyOfRange(33, 65))), p256),
        )

    override fun sha256(): ByteArray = MessageDigest.getInstance("SHA-256").digest(Inputs.message1k)

    override fun sha512(): ByteArray = MessageDigest.getInstance("SHA-512").digest(Inputs.message1k)

    override fun hmacSha256(): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(hmacKey)
            doFinal(Inputs.message1k)
        }

    // JCA has no HKDF before Java 25, and Android none at all.
    override fun hkdfSha256(): ByteArray? = null

    override fun aesGcm1k() = aesGcm(Inputs.message1k)

    override fun aesGcm16k() = aesGcm(Inputs.message16k)

    override fun chaChaPoly1k() = chacha(Inputs.message1k)

    override fun chaChaPoly16k() = chacha(Inputs.message16k)

    override fun xChaChaPoly1k(): ByteArray? = null

    override fun x25519PublicKey(): ByteArray? = null

    override fun x25519SharedSecret(): ByteArray? {
        val private = x25519Private ?: return null
        val public = x25519Public ?: return null
        return KeyAgreement.getInstance("XDH").run {
            init(private)
            doPhase(public, true)
            generateSecret()
        }
    }

    // JCA derives a public key only as part of generating a fresh pair.
    override fun p256PublicKey(): ByteArray? = null

    override fun p256SharedSecret(): ByteArray =
        KeyAgreement.getInstance("ECDH").run {
            init(p256Private)
            doPhase(p256Public, true)
            generateSecret()
        }

    override fun ed25519Sign(): ByteArray? {
        val key = ed25519Private ?: return null
        return Signature.getInstance("Ed25519").run {
            initSign(key)
            update(Inputs.message1k)
            sign()
        }
    }

    override fun ed25519Verify(): Boolean? {
        val key = ed25519Public ?: return null
        val signature = ed25519Signature ?: return null
        return Signature.getInstance("Ed25519").run {
            initVerify(key)
            update(Inputs.message1k)
            verify(signature)
        }
    }

    private fun aesGcm(message: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, nonces.next()))
            updateAAD(Inputs.aad)
            doFinal(message)
        }

    private fun chacha(message: ByteArray): ByteArray? =
        orNull {
            Cipher.getInstance("ChaCha20/Poly1305/NoPadding").run {
                init(Cipher.ENCRYPT_MODE, chachaKey, IvParameterSpec(nonces.next()))
                updateAAD(Inputs.aad)
                doFinal(message)
            }
        }

    private companion object {
        val X25519_PKCS8 = Inputs.hex("302e020100300506032b656e04220420")
        val X25519_X509 = Inputs.hex("302a300506032b656e032100")
        val ED25519_PKCS8 = Inputs.hex("302e020100300506032b657004220420")
        val ED25519_X509 = Inputs.hex("302a300506032b6570032100")

        fun der(
            prefix: ByteArray,
            key: ByteArray,
        ) = prefix + key

        /** Null where this Android version lacks the algorithm, or its key format. */
        fun <T> orNull(block: () -> T): T? =
            try {
                block()
            } catch (e: GeneralSecurityException) {
                null
            }
    }
}
