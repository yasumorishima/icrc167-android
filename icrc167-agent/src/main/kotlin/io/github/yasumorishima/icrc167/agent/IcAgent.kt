package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.ReprHash
import io.github.yasumorishima.icrc167.SignedDelegation
import io.github.yasumorishima.icrc167.systemNanos
import java.math.BigInteger

/** A request as it goes on the wire, next to the id its signature covers. */
public class SignedRequest(requestId: ByteArray, body: ByteArray) {
    private val idBytes = requestId.copyOf()
    private val bodyBytes = body.copyOf()

    public val requestId: ByteArray get() = idBytes.copyOf()
    public val body: ByteArray get() = bodyBytes.copyOf()
}

/** What a canister answered a query with. */
public sealed interface QueryReply {
    public class Replied(arg: ByteArray) : QueryReply {
        private val argBytes = arg.copyOf()
        public val arg: ByteArray get() = argBytes.copyOf()
    }

    public class Rejected(
        public val rejectCode: BigInteger,
        public val message: String,
        public val errorCode: String?,
    ) : QueryReply
}

public class IcAgentException(message: String) : RuntimeException(message)

public class HttpResponse(public val status: Int, body: ByteArray) {
    private val bodyBytes = body.copyOf()
    public val body: ByteArray get() = bodyBytes.copyOf()
}

/** Everything the agent needs from the network, so a test can stand in for it. */
public fun interface Transport {
    public fun post(url: String, body: ByteArray): HttpResponse
}

/**
 * Calls a canister as [Identity].
 *
 * What this does **not** do, said plainly, because it decides what the answer is worth: a
 * query response carries a node signature, and the interface specification defines how to
 * check it -- `verify_node_signatures` over `\x0Bic-response`, against the node public keys
 * read from a *separate* `read_state` request for `/subnet`. This module does not do that. It
 * reads the reply and hands it over.
 *
 * So the round trip is an external check on a delegation chain **only as far as the node
 * answering is honest**. That is enough for what it is for -- asking a canister which
 * principal it sees, which nothing else here can do -- and it is not enough to read state you
 * intend to trust. The certificate verification the signature check would need already lives
 * in `icrc167-certificate`; wiring it to query responses is not done.
 */
public class IcAgent(
    private val host: String = MAINNET,
    private val transport: Transport = JdkTransport(),
    private val ingressExpiry: BigInteger = FOUR_MINUTES,
    private val apiVersion: String = CURRENT_API_VERSION,
    private val clock: () -> BigInteger = { systemNanos() },
) {

    /** Builds the request without sending it. Exposed so its bytes can be measured. */
    public fun queryRequest(
        canisterId: Principal,
        method: String,
        arg: ByteArray,
        identity: Identity,
        expiryNanos: BigInteger = clock() + ingressExpiry,
    ): SignedRequest {
        // One source for both maps. The request id has to hash exactly what goes on the wire,
        // and two hand-written copies of the same six fields is how that quietly stops being
        // true.
        val content = CborItem.Dict(
            listOf(
                text("request_type") to text("query"),
                text("sender") to blob(identity.sender.bytes),
                text("canister_id") to blob(canisterId.bytes),
                text("method_name") to text(method),
                text("arg") to blob(arg),
                text("ingress_expiry") to CborItem.Uint(expiryNanos),
            ),
        )
        val requestId = ReprHash.ofMap(hashable(content))

        val envelope = ArrayList<Pair<CborItem, CborItem>>()
        envelope.add(text("content") to content)
        val auth = identity.authenticate(requestId)
        if (auth != null) {
            envelope.add(text("sender_pubkey") to blob(auth.senderPublicKey))
            envelope.add(text("sender_sig") to blob(auth.signature))
            if (auth.delegations.isNotEmpty()) {
                envelope.add(text("sender_delegation") to CborItem.Arr(auth.delegations.map(::encodeDelegation)))
            }
        }
        return SignedRequest(requestId, AgentCbor.encode(CborItem.Dict(envelope)))
    }

    /** Sends a query and returns whatever the canister answered. */
    public fun query(
        canisterId: Principal,
        method: String,
        arg: ByteArray,
        identity: Identity,
    ): QueryReply {
        val request = queryRequest(canisterId, method, arg, identity)
        val url = "$host/api/$apiVersion/canister/${canisterId.toText()}/query"
        val response = transport.post(url, request.body)
        if (response.status != 200) {
            // The replica answers a malformed or badly signed request with plain text, and
            // it names what it disliked. Passing that through is the difference between a
            // fixable failure and a silent one.
            throw IcAgentException(
                "the replica answered ${response.status}: ${describe(response.body)}",
            )
        }
        return parseReply(response.body)
    }

    /**
     * Asks a canister which principal it attributes the call to.
     *
     * The canister has to export `whoami : () -> (principal) query`. The one DFINITY runs at
     * `kvusz-kaaaa-aaaad-aabwa-cai` does.
     */
    public fun whoami(canisterId: Principal, identity: Identity): Principal =
        when (val reply = query(canisterId, "whoami", Candid.EMPTY_ARGS, identity)) {
            is QueryReply.Replied -> Candid.decodePrincipal(reply.arg)
            is QueryReply.Rejected ->
                throw IcAgentException("whoami was rejected (${reply.rejectCode}): ${reply.message}")
        }

    /** Parses a query response body. Public so recorded replies can be replayed against it. */
    public fun parseReply(bytes: ByteArray): QueryReply {
        val body = AgentCbor.textMap(AgentCbor.untag(AgentCbor.decode(bytes)))
            ?: throw IcAgentException("the reply is not a map with text keys")
        val status = (body["status"] as? CborItem.Text)?.value
            ?: throw IcAgentException("the reply carries no status")
        return when (status) {
            "replied" -> {
                val reply = AgentCbor.textMap(body["reply"] ?: throw IcAgentException("replied without a reply"))
                    ?: throw IcAgentException("the reply field is not a map")
                val arg = (reply["arg"] as? CborItem.Blob)?.bytes
                    ?: throw IcAgentException("the reply carries no arg blob")
                QueryReply.Replied(arg)
            }
            "rejected" -> QueryReply.Rejected(
                rejectCode = (body["reject_code"] as? CborItem.Uint)?.value
                    ?: throw IcAgentException("a rejection without a reject_code"),
                // Required by the specification. An empty default here would turn a
                // malformed rejection into a plausible-looking one.
                message = (body["reject_message"] as? CborItem.Text)?.value
                    ?: throw IcAgentException("a rejection without a reject_message"),
                errorCode = (body["error_code"] as? CborItem.Text)?.value,
            )
            else -> throw IcAgentException("unknown status: $status")
        }
    }

    private fun encodeDelegation(signed: SignedDelegation): CborItem {
        val delegation = signed.delegation
        val fields = ArrayList<Pair<CborItem, CborItem>>()
        fields.add(text("pubkey") to blob(delegation.pubkey))
        fields.add(text("expiration") to CborItem.Uint(delegation.expiration))
        // Absent, not empty, when the delegation is unscoped: the signature was made over a
        // map without the field, so putting an empty array here would invalidate it.
        delegation.targets?.let { targets ->
            fields.add(text("targets") to CborItem.Arr(targets.map { blob(it.bytes) }))
        }
        return CborItem.Dict(
            listOf(
                text("delegation") to CborItem.Dict(fields),
                text("signature") to blob(signed.signature),
            ),
        )
    }

    /** The content map in the form the request-id hash takes. */
    private fun hashable(content: CborItem.Dict): Map<String, ReprHash.Value> {
        val fields = LinkedHashMap<String, ReprHash.Value>(content.entries.size)
        content.entries.forEach { (key, value) ->
            val name = (key as? CborItem.Text)?.value
                ?: throw IcAgentException("a request field is not named by text")
            fields[name] = reprValue(value)
        }
        return fields
    }

    private fun reprValue(item: CborItem): ReprHash.Value = when (item) {
        is CborItem.Text -> ReprHash.Value.Text(item.value)
        is CborItem.Blob -> ReprHash.Value.Blob(item.bytes)
        is CborItem.Uint -> ReprHash.Value.Nat(item.value)
        is CborItem.Arr -> ReprHash.Value.Arr(item.items.map { reprValue(it) })
        // A request content map holds none of these, and the specification hashes nested maps
        // by a different rule. Refusing beats hashing something else.
        else -> throw IcAgentException("no request-id hash is defined for this value")
    }

    private fun text(value: String): CborItem = CborItem.Text(value)

    private fun blob(value: ByteArray): CborItem = CborItem.Blob(value)

    private fun describe(body: ByteArray): String =
        String(body, Charsets.UTF_8).filter { it.code in 32..126 }.take(500)

    public companion object {
        /** The public API boundary node. */
        public const val MAINNET: String = "https://icp-api.io"

        /**
         * `/api/v2/.../query` still answers -- measured on 2026-09-10 -- but the interface
         * specification marks it deprecated in favour of v3.
         */
        public const val CURRENT_API_VERSION: String = "v3"

        public val FOUR_MINUTES: BigInteger = BigInteger.valueOf(4L * 60 * 1_000_000_000L)
    }
}
