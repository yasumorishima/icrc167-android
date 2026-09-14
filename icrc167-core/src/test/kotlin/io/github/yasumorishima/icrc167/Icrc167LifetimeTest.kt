package io.github.yasumorishima.icrc167

import java.math.BigInteger
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject

/**
 * How long an answer may let the session key act, measured the way the IC measures it.
 *
 * A chain is usable only while every hop is, so what it grants ends at its earliest expiration.
 * Internet Identity's URL transport answers with exactly such a chain: a canister-signed hop to
 * an ephemeral key, capped at the requested lifetime, followed by a hop from that key to the
 * relying party's session key that lasts 30 days (`OUTER_DELEGATION_EXPIRATION_MS` in
 * internet-identity `src/frontend/src/lib/utils/transport/url.ts`). A real phone sign-in was
 * refused with "delegation outlives the requested maxTimeToLive" because each hop was compared
 * on its own (2026-09-14).
 */
class Icrc167LifetimeTest {

    private val callback = "https://example.org/icrc167-callback"
    private val thirtyDays = BigInteger.valueOf(30L * 24 * 60 * 60 * 1_000_000_000)

    /** `root -> intermediate -> session`, each hop with its own expiration. */
    private fun twoHopReply(
        request: Icrc167AuthRequest,
        root: TestKey,
        intermediate: TestKey,
        session: TestKey,
        innerExpiration: BigInteger,
        outerExpiration: BigInteger,
    ): String {
        val sent = Fragment.decode(request.authorizationUrl().substringAfter('#'))
        val id = JSONObject(sent.getValue("message")).getString("id")

        fun hop(signer: TestKey, next: TestKey, expiration: BigInteger): JSONObject {
            val delegation = Delegation(next.der, expiration)
            return JSONObject()
                .put("delegation", JSONObject().put("pubkey", b64(next.der)).put("expiration", expiration.toString()))
                .put("signature", b64(signer.sign(delegation.signableBytes())))
        }

        val response = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put(
                "result",
                JSONObject()
                    .put("publicKey", b64(root.der))
                    .put(
                        "signerDelegation",
                        JSONArray()
                            .put(hop(root, intermediate, innerExpiration))
                            .put(hop(intermediate, session, outerExpiration)),
                    ),
            )
        val fragment = Fragment.encode(linkedMapOf("message" to response.toString(), "state" to sent.getValue("state")))
        return "$callback#$fragment"
    }

    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    @Test
    fun `accepts Internet Identity's URL-transport chain, whose last hop outlives the request`() {
        val root = TestKey.generate()
        val intermediate = TestKey.generate()
        val session = TestKey.generate()
        val req = Icrc167.delegationRequest(callback = callback, sessionPublicKeyDer = session.der)

        val result = req.complete(
            twoHopReply(
                req, root, intermediate, session,
                innerExpiration = nanosFromNow(3600),
                outerExpiration = nowNanos().add(thirtyDays),
            ),
        )

        assertIs<Icrc167Result.Authenticated>(result)
        assertEquals(2, result.chain.delegations.size)
        // The chain still has to verify end to end: the lifetime check does not replace it.
        assertIs<ChainVerification.Valid>(DelegationChainVerifier(ed25519Verifier).verify(result.chain, session.der, nowNanos()))
    }

    @Test
    fun `measures the earliest hop, not the first one`() {
        // Pins the rule itself: checking only the first hop would refuse this chain, which
        // lives one hour because its second hop does.
        val root = TestKey.generate()
        val intermediate = TestKey.generate()
        val session = TestKey.generate()
        val req = Icrc167.delegationRequest(callback = callback, sessionPublicKeyDer = session.der)

        val result = req.complete(
            twoHopReply(
                req, root, intermediate, session,
                innerExpiration = nowNanos().add(thirtyDays),
                outerExpiration = nanosFromNow(3600),
            ),
        )

        assertIs<Icrc167Result.Authenticated>(result)
    }

    @Test
    fun `refuses a chain in which every hop outlives the request`() {
        val root = TestKey.generate()
        val intermediate = TestKey.generate()
        val session = TestKey.generate()
        val req = Icrc167.delegationRequest(callback = callback, sessionPublicKeyDer = session.der)

        val result = req.complete(
            twoHopReply(
                req, root, intermediate, session,
                innerExpiration = nowNanos().add(thirtyDays),
                outerExpiration = nowNanos().add(thirtyDays),
            ),
        )

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("maxTimeToLive"))
    }
}
