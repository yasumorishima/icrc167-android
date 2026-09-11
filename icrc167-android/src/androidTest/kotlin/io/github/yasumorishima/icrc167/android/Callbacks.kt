package io.github.yasumorishima.icrc167.android

import io.github.yasumorishima.icrc167.Delegation
import io.github.yasumorishima.icrc167.systemNanos
import java.math.BigInteger
import java.net.URLEncoder
import java.security.SecureRandom
import java.util.Base64
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Answers a pending attempt the way a signer would, so the client can be driven end to end on
 * a device without Internet Identity.
 *
 * The answer is assembled by hand rather than through the library's own fragment codec, so a
 * test does not check that codec against itself. The fake signer does it this way for the
 * same reason.
 */
internal object Callbacks {
    /** Never fetched: the tests hand the link to the client directly. */
    const val URL = "https://icrc167-test.invalid/auth"

    class Answer(val url: String, val rootPublicKeyDer: ByteArray)

    fun answer(pending: Icrc167Client.Pending, corruptSignature: Boolean = false): Answer {
        val root = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(SecureRandom()))
        }.generateKeyPair().private as Ed25519PrivateKeyParameters
        val rootDer = SPKI_PREFIX + root.generatePublicKey().encoded

        val expiration = systemNanos() + ONE_HOUR_NANOS
        val signable = Delegation(pending.sessionPublicKeyDer, expiration).signableBytes()
        val signature = Ed25519Signer().apply {
            init(true, root)
            update(signable, 0, signable.size)
        }.generateSignature()
        if (corruptSignature) signature[0] = (signature[0].toInt() xor 0x01).toByte()

        val b64 = Base64.getEncoder()
        val message = """{"jsonrpc":"2.0","id":"${pending.requestId}","result":{""" +
            """"publicKey":"${b64.encodeToString(rootDer)}","signerDelegation":[{"delegation":{""" +
            """"pubkey":"${b64.encodeToString(pending.sessionPublicKeyDer)}","expiration":"$expiration"},""" +
            """"signature":"${b64.encodeToString(signature)}"}]}}"""
        val fragment = "message=" + encode(message) + "&state=" + encode(pending.state)
        return Answer("$URL#$fragment", rootDer)
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

    /** RFC 8410 SubjectPublicKeyInfo header for an Ed25519 key, followed by 32 raw bytes. */
    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    private val ONE_HOUR_NANOS: BigInteger = BigInteger.valueOf(60L * 60 * 1_000_000_000)
}
