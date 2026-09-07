package io.github.yasumorishima.icrc167.fakesigner

import io.github.yasumorishima.icrc167.Delegation
import io.github.yasumorishima.icrc167.Principal
import java.math.BigInteger
import java.net.URLEncoder
import java.security.SecureRandom
import java.util.Base64
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Stands in for Internet Identity so the return path can be exercised end to end without a
 * passkey, a real domain, or a network.
 *
 * It is a real signer in every respect that matters to the client: it produces a delegation
 * over the app's own session key and signs it, so the app has to hash, verify and derive a
 * principal for real. What it is not is Internet Identity — there is no canister signature
 * here, and no human decided anything.
 *
 * The fragment is assembled with plain `URLEncoder` rather than the library's own codec, so
 * the test does not check an encoder against itself.
 */
fun main(args: Array<String>) {
    require(args.size == 4) {
        "usage: <callbackUrl> <sessionPublicKeyDerBase64> <requestId> <state>"
    }
    val callbackUrl = args[0]
    val sessionPublicKeyDer = Base64.getDecoder().decode(args[1])
    val requestId = args[2]
    val state = args[3]

    val root = Ed25519Key()
    val expiration = BigInteger.valueOf(System.currentTimeMillis() + ONE_HOUR_MILLIS)
        .multiply(BigInteger.valueOf(1_000_000))

    val delegation = Delegation(sessionPublicKeyDer, expiration)
    val signature = root.sign(delegation.signableBytes())

    val message = buildString {
        append("""{"jsonrpc":"2.0","id":""").append(quote(requestId)).append(""","result":{""")
        append(""""publicKey":""").append(quote(base64(root.der)))
        append(""","signerDelegation":[{"delegation":{""")
        append(""""pubkey":""").append(quote(base64(sessionPublicKeyDer)))
        append(""","expiration":""").append(quote(expiration.toString()))
        append("""},"signature":""").append(quote(base64(signature))).append("""}]}}""")
    }

    val fragment = "message=${encode(message)}&state=${encode(state)}"
    println("CALLBACK_URL=$callbackUrl#$fragment")
    println("EXPECTED_PRINCIPAL=${Principal.selfAuthenticating(root.der).toText()}")
}

private const val ONE_HOUR_MILLIS = 60L * 60 * 1000

private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

private fun quote(value: String): String = "\"" + value.replace("\"", "\\\"") + "\""

private class Ed25519Key {
    private val privateKey: Ed25519PrivateKeyParameters
    private val publicKey: Ed25519PublicKeyParameters

    init {
        val generator = Ed25519KeyPairGenerator()
        generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val pair = generator.generateKeyPair()
        privateKey = pair.private as Ed25519PrivateKeyParameters
        publicKey = pair.public as Ed25519PublicKeyParameters
    }

    /** RFC 8410 SubjectPublicKeyInfo: fixed header, then the 32 raw bytes. */
    val der: ByteArray
        get() = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ) + publicKey.encoded

    fun sign(message: ByteArray): ByteArray = Ed25519Signer().apply {
        init(true, privateKey)
        update(message, 0, message.size)
    }.generateSignature()
}
