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
 * principal for real. What it is not is Internet Identity: no human decided anything, and the
 * one canister signature it can produce (`canister-root`) is deliberately one that cannot verify.
 *
 * The fragment is assembled with plain `URLEncoder` rather than the library's own codec, so
 * the test does not check an encoder against itself.
 */
fun main(args: Array<String>) {
    require(args.size == 4 || args.size == 5) {
        "usage: <callbackUrl> <sessionPublicKeyDerBase64> <requestId> <state> " +
            "[valid|bad-signature|wrong-state|canister-root]"
    }
    val callbackUrl = args[0]
    val sessionPublicKeyDer = Base64.getDecoder().decode(args[1])
    val requestId = args[2]
    val requestedState = args[3]
    val mode = if (args.size == 5) args[4] else "valid"
    require(mode in setOf("valid", "bad-signature", "wrong-state", "canister-root")) { "unknown mode: $mode" }

    // The client must not accept a chain whose signature does not check out, and must not
    // accept an answer bound to somebody else's attempt. Both are answers a real signer would
    // never give, which is exactly why the test has to manufacture them.
    val state = if (mode == "wrong-state") "not-the-state-that-was-asked-for" else requestedState

    val root = Ed25519Key()
    val expiration = BigInteger.valueOf(System.currentTimeMillis() + ONE_HOUR_MILLIS)
        .multiply(BigInteger.valueOf(1_000_000))

    val delegation = Delegation(sessionPublicKeyDer, expiration)
    val signature = root.sign(delegation.signableBytes()).also {
        if (mode == "bad-signature") it[0] = (it[0].toInt() xor 0x01).toByte()
    }

    // A root key that names the canister-signature scheme, over a signature that cannot be one.
    // What the client says about it shows which verifier looked: BadSignature means the
    // canister-signature verifier took the key and refused the proof, UnsupportedKey means no
    // verifier recognised the scheme at all -- the answer every real chain would then get.
    val rootDer = if (mode == "canister-root") canisterSignatureKey() else root.der
    val rootSignature = if (mode == "canister-root") NOT_A_CANISTER_SIGNATURE else signature

    val message = buildString {
        append("""{"jsonrpc":"2.0","id":""").append(quote(requestId)).append(""","result":{""")
        append(""""publicKey":""").append(quote(base64(rootDer)))
        append(""","signerDelegation":[{"delegation":{""")
        append(""""pubkey":""").append(quote(base64(sessionPublicKeyDer)))
        append(""","expiration":""").append(quote(expiration.toString()))
        append("""},"signature":""").append(quote(base64(rootSignature))).append("""}]}}""")
    }

    val fragment = "message=${encode(message)}&state=${encode(state)}"
    println("CALLBACK_URL=$callbackUrl#$fragment")
    println("EXPECTED_PRINCIPAL=${Principal.selfAuthenticating(rootDer).toText()}")
}

private const val ONE_HOUR_MILLIS = 60L * 60 * 1000

/**
 * The self-describe tag with nothing after it. The canister-signature parser has to refuse this
 * as malformed CBOR, so the verifier answers INVALID without reaching any certificate.
 */
private val NOT_A_CANISTER_SIGNATURE = byteArrayOf(0xd9.toByte(), 0xd9.toByte(), 0xf7.toByte())

/**
 * A canister-signature public key, assembled by hand rather than through the library so the
 * test does not check the parser against itself: a SubjectPublicKeyInfo with OID
 * 1.3.6.1.4.1.56387.1.2 whose bit string is the length of a canister id, the id, and a seed.
 */
private fun canisterSignatureKey(): ByteArray {
    // Internet Identity's own canister, rdmx6-jaaaa-aaaaa-aaadq-cai.
    val canisterId = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 7, 1, 1)
    val seed = ByteArray(32).also { SecureRandom().nextBytes(it) }
    val oid = byteArrayOf(
        0x2B, 0x06, 0x01, 0x04, 0x01, 0x83.toByte(), 0xB8.toByte(), 0x43, 0x01, 0x02,
    )
    val algorithm = der(0x30, der(0x06, oid))
    val bitString = der(0x03, byteArrayOf(0, canisterId.size.toByte()) + canisterId + seed)
    return der(0x30, algorithm + bitString)
}

/** One DER element with a short-form length. Everything here is under 128 bytes. */
private fun der(tag: Int, content: ByteArray): ByteArray {
    require(content.size < 128) { "short-form length only, got ${content.size}" }
    return byteArrayOf(tag.toByte(), content.size.toByte()) + content
}

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
