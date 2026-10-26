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

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519
import org.bouncycastle.util.BigIntegers
import java.math.BigInteger

/** Bouncy Castle's lightweight API, the usual pure-Java fallback on Android. */
class BouncyCastleOperations : Operations {
    private val nonces = NonceCounter()
    private val ed25519Public = ByteArray(Ed25519.PUBLIC_KEY_SIZE).also { Ed25519.generatePublicKey(Inputs.ed25519Seed, 0, it, 0) }
    private val ed25519Signature = ed25519Sign()
    private val p256 = CustomNamedCurves.getByName("secp256r1").let { ECDomainParameters(it.curve, it.g, it.n, it.h) }
    private val p256Private = ECPrivateKeyParameters(BigInteger(1, Inputs.p256Private), p256)
    private val p256Public = ECPublicKeyParameters(p256.curve.decodePoint(Inputs.p256Public), p256)

    override fun sha256(): ByteArray {
        val digest = SHA256Digest()
        digest.update(Inputs.message1k, 0, Inputs.message1k.size)
        return ByteArray(32).also { digest.doFinal(it, 0) }
    }

    override fun sha512(): ByteArray {
        val digest = SHA512Digest()
        digest.update(Inputs.message1k, 0, Inputs.message1k.size)
        return ByteArray(64).also { digest.doFinal(it, 0) }
    }

    override fun hmacSha256(): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(Inputs.hmacKey))
        mac.update(Inputs.message1k, 0, Inputs.message1k.size)
        return ByteArray(32).also { mac.doFinal(it, 0) }
    }

    override fun hkdfSha256(): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(Inputs.hmacKey, Inputs.aad, Inputs.aad))
        return ByteArray(32).also { hkdf.generateBytes(it, 0, 32) }
    }

    override fun aesGcm1k() = aesGcm(Inputs.message1k)

    override fun aesGcm16k() = aesGcm(Inputs.message16k)

    override fun chaChaPoly1k() = chacha(Inputs.message1k)

    override fun chaChaPoly16k() = chacha(Inputs.message16k)

    override fun xChaChaPoly1k(): ByteArray? = null

    override fun x25519PublicKey() = ByteArray(X25519.POINT_SIZE).also { X25519.generatePublicKey(Inputs.x25519Private, 0, it, 0) }

    override fun x25519SharedSecret() =
        ByteArray(X25519.POINT_SIZE).also {
            X25519.calculateAgreement(Inputs.x25519Private, 0, Inputs.x25519Public, 0, it, 0)
        }

    override fun p256PublicKey(): ByteArray =
        p256.g
            .multiply(p256Private.d)
            .normalize()
            .getEncoded(false)

    override fun p256SharedSecret(): ByteArray = BigIntegers.asUnsignedByteArray(32, ECDHBasicAgreement().apply { init(p256Private) }.calculateAgreement(p256Public))

    override fun ed25519Sign() =
        ByteArray(Ed25519.SIGNATURE_SIZE).also {
            Ed25519.sign(Inputs.ed25519Seed, 0, ed25519Public, 0, Inputs.message1k, 0, Inputs.message1k.size, it, 0)
        }

    override fun ed25519Verify() = Ed25519.verify(ed25519Signature, 0, ed25519Public, 0, Inputs.message1k, 0, Inputs.message1k.size)

    private fun aesGcm(message: ByteArray): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        cipher.init(true, AEADParameters(KeyParameter(Inputs.aesKey), 128, nonces.next(), Inputs.aad))
        val out = ByteArray(cipher.getOutputSize(message.size))
        val n = cipher.processBytes(message, 0, message.size, out, 0)
        cipher.doFinal(out, n)
        return out
    }

    private fun chacha(message: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(Inputs.chachaKey), 128, nonces.next(), Inputs.aad))
        val out = ByteArray(cipher.getOutputSize(message.size))
        val n = cipher.processBytes(message, 0, message.size, out, 0)
        cipher.doFinal(out, n)
        return out
    }
}
