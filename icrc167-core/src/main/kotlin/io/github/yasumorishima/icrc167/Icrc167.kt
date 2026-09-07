package io.github.yasumorishima.icrc167

import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/** Outcome of a signer round-trip. The chain is *not* verified here — see [DelegationChainVerifier]. */
public sealed interface Icrc167Result {
    /** The signer returned a chain. It still has to be verified before it is trusted. */
    public data class Authenticated(val chain: DelegationChain) : Icrc167Result

    /** The signer answered with a JSON-RPC error, e.g. the user refused. */
    public data class SignerError(val code: Int, val message: String) : Icrc167Result

    /** The callback did not belong to this request, or was malformed. */
    public data class Rejected(val reason: String) : Icrc167Result
}

/**
 * Builds an ICRC-167 `icrc34_delegation` request and validates the callback that answers it.
 *
 * One instance corresponds to exactly one authentication attempt: the `state` nonce and the
 * JSON-RPC id are generated here, and [complete] may only succeed once.
 */
public class Icrc167AuthRequest internal constructor(
    private val signerUrl: String,
    private val callback: String,
    private val requestId: String,
    private val state: String,
    sessionPublicKeyDer: ByteArray,
    private val maxTimeToLiveNanos: BigInteger,
    private val targets: List<Principal>?,
) {
    private val sessionPublicKey = sessionPublicKeyDer.copyOf()
    private var consumed = false

    /** The URL to open in the browser. */
    public fun authorizationUrl(): String {
        val params = LinkedHashMap<String, String>()
        params["message"] = jsonRpcRequest().toString()
        params["callback"] = callback
        params["state"] = state
        return signerUrl + "#" + Fragment.encode(params)
    }

    private fun jsonRpcRequest(): JSONObject {
        val params = JSONObject()
            .put("publicKey", Base64.getEncoder().encodeToString(sessionPublicKey))
            .put("maxTimeToLive", maxTimeToLiveNanos.toString())
        if (targets != null) {
            params.put("targets", JSONArray(targets.map { it.toText() }))
        }
        return JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", requestId)
            .put("method", "icrc34_delegation")
            .put("params", params)
    }

    /**
     * Validates the URL the signer navigated back to and extracts the chain.
     *
     * Everything that binds this response to *this* request is checked here: the callback URL
     * itself, the `state` nonce, and the JSON-RPC id.
     */
    public fun complete(callbackUri: String): Icrc167Result {
        if (consumed) return Icrc167Result.Rejected("this request has already been completed")

        val separator = callbackUri.indexOf('#')
        if (separator < 0) return Icrc167Result.Rejected("callback carries no fragment")
        val base = callbackUri.substring(0, separator)
        val fragment = callbackUri.substring(separator + 1)

        // The signer must return to the exact URL we declared. Comparing the whole prefix
        // also rules out a response arriving on a different declared callback.
        if (base != callback) return Icrc167Result.Rejected("callback URL does not match the request")

        val params = try {
            Fragment.decode(fragment)
        } catch (e: IllegalArgumentException) {
            return Icrc167Result.Rejected("malformed fragment: ${e.message}")
        }

        val returnedState = params["state"]
            ?: return Icrc167Result.Rejected("callback carries no state")
        if (!constantTimeEquals(returnedState, state)) {
            return Icrc167Result.Rejected("state does not match this request")
        }

        val message = params["message"] ?: return Icrc167Result.Rejected("callback carries no message")

        // Only mark the attempt spent once the response is provably ours, so that a stray or
        // forged callback cannot burn a pending login.
        consumed = true

        return try {
            parseResponse(message)
        } catch (e: Exception) {
            Icrc167Result.Rejected("malformed response: ${e.message}")
        }
    }

    private fun parseResponse(message: String): Icrc167Result {
        val trimmed = message.trimStart()
        val response: JSONObject = if (trimmed.startsWith("[")) {
            val batch = JSONArray(message)
            (0 until batch.length())
                .map { batch.getJSONObject(it) }
                .firstOrNull { it.optString("id") == requestId }
                ?: return Icrc167Result.Rejected("no response in batch matches our request id")
        } else {
            JSONObject(message)
        }

        if (response.optString("id") != requestId) {
            return Icrc167Result.Rejected("response id does not match this request")
        }
        if (response.has("error")) {
            val error = response.getJSONObject("error")
            return Icrc167Result.SignerError(
                code = error.optInt("code"),
                message = error.optString("message"),
            )
        }

        val result = response.optJSONObject("result")
            ?: return Icrc167Result.Rejected("response has neither result nor error")

        val decoder = Base64.getDecoder()
        val rootPublicKey = decoder.decode(result.getString("publicKey"))
        val signed = result.getJSONArray("signerDelegation")
        val delegations = (0 until signed.length()).map { index ->
            val entry = signed.getJSONObject(index)
            val delegation = entry.getJSONObject("delegation")
            val targetList = delegation.optJSONArray("targets")?.let { array ->
                (0 until array.length()).map { Principal.fromText(array.getString(it)) }
            }
            SignedDelegation(
                delegation = Delegation(
                    pubkey = decoder.decode(delegation.getString("pubkey")),
                    expiration = BigInteger(delegation.getString("expiration")),
                    targets = targetList,
                ),
                signature = decoder.decode(entry.getString("signature")),
            )
        }
        return Icrc167Result.Authenticated(DelegationChain(rootPublicKey, delegations))
    }

    /** The session key this request is bound to; the chain must terminate at it. */
    public fun sessionPublicKeyDer(): ByteArray = sessionPublicKey.copyOf()

    private fun constantTimeEquals(a: String, b: String): Boolean {
        val left = a.toByteArray(Charsets.UTF_8)
        val right = b.toByteArray(Charsets.UTF_8)
        if (left.size != right.size) return false
        var diff = 0
        for (i in left.indices) diff = diff or (left[i].toInt() xor right[i].toInt())
        return diff == 0
    }
}

public object Icrc167 {

    /** Internet Identity's production transport URL. */
    public const val INTERNET_IDENTITY_URL: String = "https://id.ai/authorize"

    public val EIGHT_HOURS_NANOS: BigInteger = BigInteger.valueOf(8L * 60 * 60 * 1_000_000_000)

    private val random = SecureRandom()

    /**
     * @param callback must be listed verbatim in `/.well-known/ii-auth-callbacks` on its own
     *   origin, and must not carry a fragment — the signer appends its own.
     * @param targets omit to receive the ordinary relying-party principal. Supplying targets
     *   can yield a *different* principal (an ICRC-34 account delegation).
     */
    public fun delegationRequest(
        callback: String,
        sessionPublicKeyDer: ByteArray,
        signerUrl: String = INTERNET_IDENTITY_URL,
        maxTimeToLiveNanos: BigInteger = EIGHT_HOURS_NANOS,
        targets: List<Principal>? = null,
    ): Icrc167AuthRequest {
        require(!callback.contains('#')) { "the callback URL must not contain a fragment" }
        require(callback.startsWith("https://")) { "the callback URL must be https" }
        require(!signerUrl.contains('#')) { "the signer URL must not contain a fragment" }
        require(targets == null || targets.isNotEmpty()) {
            "targets must be null or non-empty; an empty list means something different"
        }
        return Icrc167AuthRequest(
            signerUrl = signerUrl,
            callback = callback,
            requestId = nonce(8),
            state = nonce(16),
            sessionPublicKeyDer = sessionPublicKeyDer,
            maxTimeToLiveNanos = maxTimeToLiveNanos,
            targets = targets,
        )
    }

    private fun nonce(bytes: Int): String {
        val buffer = ByteArray(bytes)
        random.nextBytes(buffer)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer)
    }
}
