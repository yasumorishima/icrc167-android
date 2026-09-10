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
 * Scope, stated plainly: this sends **query** calls, and a query reply is not certified. The
 * node signatures that come back with it are not checked here, and checking them would not
 * make the answer authoritative anyway. That is fine for what this is for -- asking a
 * canister which principal it sees, which is the only way to test a delegation chain from
 * the outside end to end -- and it is not fine as a way to read state you intend to trust.
 * For that, an update call plus a certified `read_state` is the shape, and the certificate
 * verification for it already lives in `icrc167-certificate`.
 */
public class IcAgent(
    private val host: String = MAINNET,
    private val transport: Transport = JdkTransport(),
    private val ingressExpiry: BigInteger = FOUR_MINUTES,
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
        val fields = LinkedHashMap<String, ReprHash.Value>()
        fields["request_type"] = ReprHash.Value.Text("query")
        fields["sender"] = ReprHash.Value.Blob(identity.sender.bytes)
        fields["canister_id"] = ReprHash.Value.Blob(canisterId.bytes)
        fields["method_name"] = ReprHash.Value.Text(method)
        fields["arg"] = ReprHash.Value.Blob(arg)
        fields["ingress_expiry"] = ReprHash.Value.Nat(expiryNanos)
        val requestId = ReprHash.ofMap(fields)

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
        val url = "$host/api/v2/canister/${canisterId.toText()}/query"
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
                message = (body["reject_message"] as? CborItem.Text)?.value ?: "",
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

    private fun text(value: String): CborItem = CborItem.Text(value)

    private fun blob(value: ByteArray): CborItem = CborItem.Blob(value)

    private fun describe(body: ByteArray): String =
        String(body, Charsets.UTF_8).take(500).filter { it.code in 32..126 }

    public companion object {
        /** The public API boundary node. */
        public const val MAINNET: String = "https://icp-api.io"

        public val FOUR_MINUTES: BigInteger = BigInteger.valueOf(4L * 60 * 1_000_000_000L)
    }
}
