package io.github.yasumorishima.icrc167

import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONArray
import org.json.JSONObject

/** Outcome of a signer round-trip. The chain is *not* verified here — see [DelegationChainVerifier]. */
public sealed interface Icrc167Result {
    /**
     * The signer returned a chain. It still has to be verified before it is trusted.
     *
     * [effectiveTargets] is the intersection of the scopes the chain carries, or `null` when
     * the chain is unscoped. Requesting targets does **not** guarantee a scoped answer: by
     * ICRC-34 a signer that cannot establish trust for the target canisters falls back to an
     * ordinary relying-party delegation. That is a legitimate outcome and it changes the
     * principal, so it is reported rather than hidden or refused.
     */
    public data class Authenticated(
        val chain: DelegationChain,
        val effectiveTargets: List<Principal>?,
    ) : Icrc167Result

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
    /**
     * The JSON-RPC id and the `state` nonce. Public so that an attempt can outlive the
     * process: the browser is in the foreground for as long as the user takes to
     * authenticate, and Android may reclaim us in the meantime. Persist these with
     * [Icrc167.restoreRequest] rather than losing a sign-in to a background kill.
     */
    public val requestId: String,
    public val state: String,
    sessionPublicKeyDer: ByteArray,
    private val maxTimeToLiveNanos: BigInteger,
    private val targets: List<Principal>?,
) {
    private val sessionPublicKey = sessionPublicKeyDer.copyOf()
    private val consumed = AtomicBoolean(false)

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
            .put("jsonrpc", JSON_RPC_VERSION)
            .put("id", requestId)
            .put("method", "icrc34_delegation")
            .put("params", params)
    }

    /**
     * Validates the URL the signer navigated back to and extracts the chain.
     *
     * Everything that binds this response to *this* request is checked here: the callback URL
     * itself, the `state` nonce, the JSON-RPC id, and that the granted scope does not exceed
     * what was asked for.
     */
    public fun complete(
        callbackUri: String,
        nowNanos: BigInteger = systemNanos(),
    ): Icrc167Result {
        val separator = callbackUri.indexOf('#')
        if (separator < 0) return Icrc167Result.Rejected("callback carries no fragment")
        val base = callbackUri.substring(0, separator)
        val fragment = callbackUri.substring(separator + 1)

        // The signer must return to the URL we declared. Scheme and host are compared
        // case-insensitively because RFC 3986 says they are; the rest is compared exactly.
        if (!sameUrl(base, callback)) {
            return Icrc167Result.Rejected("callback URL does not match the request")
        }

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
        if (!consumed.compareAndSet(false, true)) {
            return Icrc167Result.Rejected("this request has already been completed")
        }

        return try {
            parseResponse(message, nowNanos)
        } catch (e: Exception) {
            Icrc167Result.Rejected("malformed response: ${e.message}")
        }
    }

    private fun parseResponse(message: String, nowNanos: BigInteger): Icrc167Result {
        val trimmed = message.trimStart()
        val response: JSONObject = if (trimmed.startsWith("[")) {
            val batch = JSONArray(message)
            val matching = (0 until batch.length())
                .map { batch.getJSONObject(it) }
                .filter { it.optString("id") == requestId }
            // More than one answer to the same request is malformed, and picking either one
            // means letting the sender choose which we act on.
            when (matching.size) {
                1 -> matching.single()
                0 -> return Icrc167Result.Rejected("no response in batch matches our request id")
                else -> return Icrc167Result.Rejected("batch contains multiple responses for our request id")
            }
        } else {
            JSONObject(message)
        }

        if (response.optString("jsonrpc") != JSON_RPC_VERSION) {
            return Icrc167Result.Rejected("response is not JSON-RPC $JSON_RPC_VERSION")
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

        // A signer may shorten the lifetime but must not extend it. The tolerance absorbs
        // clock skew between us and the signer, not a materially longer grant.
        val latestAcceptable = nowNanos + maxTimeToLiveNanos + CLOCK_SKEW_NANOS
        delegations.forEach { hop ->
            if (hop.delegation.expiration > latestAcceptable) {
                return Icrc167Result.Rejected("delegation outlives the requested maxTimeToLive")
            }
        }

        val scopes = delegations.mapNotNull { it.delegation.targets }
        if (targets != null) {
            // Never accept more authority than was asked for. (Receiving *less* — including
            // an unscoped relying-party delegation — is a legitimate ICRC-34 outcome.)
            scopes.forEach { scope ->
                if (!targets.containsAll(scope)) {
                    return Icrc167Result.Rejected("delegation scope exceeds the requested targets")
                }
            }
        }
        val effective = scopes.reduceOrNull { acc, next -> acc.filter { it in next } }

        return Icrc167Result.Authenticated(
            chain = DelegationChain(rootPublicKey, delegations),
            effectiveTargets = effective,
        )
    }

    /** The session key this request is bound to; the chain must terminate at it. */
    public fun sessionPublicKeyDer(): ByteArray = sessionPublicKey.copyOf()

    private fun sameUrl(received: String, declared: String): Boolean =
        normaliseOrigin(received) == normaliseOrigin(declared)

    private fun normaliseOrigin(url: String): String {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return url
        val authorityEnd = url.indexOf('/', schemeEnd + 3).let { if (it < 0) url.length else it }
        return url.substring(0, authorityEnd).lowercase() + url.substring(authorityEnd)
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        val left = a.toByteArray(Charsets.UTF_8)
        val right = b.toByteArray(Charsets.UTF_8)
        if (left.size != right.size) return false
        var diff = 0
        for (i in left.indices) diff = diff or (left[i].toInt() xor right[i].toInt())
        return diff == 0
    }

    private companion object {
        const val JSON_RPC_VERSION = "2.0"
        val CLOCK_SKEW_NANOS: BigInteger = BigInteger.valueOf(5L * 60 * 1_000_000_000)
    }
}

/** Nanoseconds since the epoch, at millisecond resolution — what the IC expresses times in. */
public fun systemNanos(): BigInteger =
    BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(1_000_000))

public object Icrc167 {

    /** Internet Identity's production transport URL. */
    public const val INTERNET_IDENTITY_URL: String = "https://id.ai/authorize"

    public val EIGHT_HOURS_NANOS: BigInteger = BigInteger.valueOf(8L * 60 * 60 * 1_000_000_000)

    private val random = SecureRandom()

    /**
     * @param callback must be listed verbatim in `/.well-known/ii-auth-callbacks` on its own
     *   origin, and must not carry a fragment — the signer appends its own.
     * @param targets omit to receive the ordinary relying-party principal. Supplying targets
     *   can yield a *different* principal (an ICRC-34 account delegation), and does not
     *   guarantee a scoped answer; check `Authenticated.effectiveTargets`.
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
        // Over http, anyone on the path can inject script into the signer page and read the
        // state out of location.hash, then answer with a chain for an identity of their
        // choosing. The request would still look correct to us.
        require(signerUrl.startsWith("https://")) { "the signer URL must be https" }
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

    /**
     * Rebuilds a pending attempt whose process was killed while the browser was in front.
     *
     * The caller is responsible for having stored [requestId] and [state] alongside the
     * session key; passing values that did not come from a real [delegationRequest] only
     * guarantees that no callback will ever match.
     */
    public fun restoreRequest(
        callback: String,
        sessionPublicKeyDer: ByteArray,
        requestId: String,
        state: String,
        signerUrl: String = INTERNET_IDENTITY_URL,
        maxTimeToLiveNanos: BigInteger = EIGHT_HOURS_NANOS,
        targets: List<Principal>? = null,
    ): Icrc167AuthRequest = Icrc167AuthRequest(
        signerUrl = signerUrl,
        callback = callback,
        requestId = requestId,
        state = state,
        sessionPublicKeyDer = sessionPublicKeyDer,
        maxTimeToLiveNanos = maxTimeToLiveNanos,
        targets = targets,
    )

    private fun nonce(bytes: Int): String {
        val buffer = ByteArray(bytes)
        random.nextBytes(buffer)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer)
    }
}
