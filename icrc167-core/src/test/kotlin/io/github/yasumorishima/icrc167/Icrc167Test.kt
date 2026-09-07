package io.github.yasumorishima.icrc167

import java.math.BigInteger
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject

class Icrc167Test {

    private val callback = "https://example.org/icrc167-callback"

    private fun newRequest(session: TestKey) = Icrc167.delegationRequest(
        callback = callback,
        sessionPublicKeyDer = session.der,
        signerUrl = "https://id.ai/authorize",
    )

    /** The signer's side of the round trip, as ICRC-167 defines it. */
    private fun signerReply(
        request: Icrc167AuthRequest,
        root: TestKey,
        session: TestKey,
        expiration: BigInteger = nanosFromNow(3600),
        overrideState: String? = null,
        overrideId: String? = null,
    ): String {
        val sent = Fragment.decode(request.authorizationUrl().substringAfter('#'))
        val id = overrideId ?: JSONObject(sent.getValue("message")).getString("id")

        val delegation = Delegation(session.der, expiration)
        val message = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put(
                "result",
                JSONObject()
                    .put("publicKey", b64(root.der))
                    .put(
                        "signerDelegation",
                        JSONArray().put(
                            JSONObject()
                                .put(
                                    "delegation",
                                    JSONObject()
                                        .put("pubkey", b64(session.der))
                                        .put("expiration", expiration.toString()),
                                )
                                .put("signature", b64(root.sign(delegation.signableBytes()))),
                        ),
                    ),
            )
        val fragment = Fragment.encode(
            linkedMapOf(
                "message" to message.toString(),
                "state" to (overrideState ?: sent.getValue("state")),
            ),
        )
        return "$callback#$fragment"
    }

    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    @Test
    fun `the authorization URL carries the request in the fragment, not the query`() {
        val session = TestKey.generate()
        val url = newRequest(session).authorizationUrl()

        assertTrue(url.startsWith("https://id.ai/authorize#"))
        // Nothing may appear before the '#': the payload must never reach a server.
        assertTrue(!url.substringBefore('#').contains('?'))

        val params = Fragment.decode(url.substringAfter('#'))
        assertEquals(callback, params["callback"])
        assertTrue(params.containsKey("state"))

        val message = JSONObject(params.getValue("message"))
        assertEquals("2.0", message.getString("jsonrpc"))
        assertEquals("icrc34_delegation", message.getString("method"))
        assertEquals(
            b64(session.der),
            message.getJSONObject("params").getString("publicKey"),
        )
    }

    @Test
    fun `a well formed reply yields a chain that verifies against our session key`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val request = newRequest(session)

        val result = request.complete(signerReply(request, root, session))

        assertIs<Icrc167Result.Authenticated>(result)
        val verification = DelegationChainVerifier(ed25519Verifier)
            .verify(result.chain, session.der, nowNanos())
        assertIs<ChainVerification.Valid>(verification)
        assertEquals(Principal.selfAuthenticating(root.der), verification.principal)
    }

    @Test
    fun `rejects a reply carrying a different state`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val request = newRequest(session)

        val result = request.complete(
            signerReply(request, root, session, overrideState = "not-our-state"),
        )

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("state"))
    }

    @Test
    fun `rejects a reply whose JSON-RPC id is not ours`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val request = newRequest(session)

        val result = request.complete(signerReply(request, root, session, overrideId = "99"))

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("id"))
    }

    @Test
    fun `rejects a reply delivered to a different callback URL`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val request = newRequest(session)
        val reply = signerReply(request, root, session)
            .replace("https://example.org/", "https://evil.example/")

        val result = request.complete(reply)

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("callback"))
    }

    @Test
    fun `a request can only be completed once`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val request = newRequest(session)
        val reply = signerReply(request, root, session)

        assertIs<Icrc167Result.Authenticated>(request.complete(reply))
        assertIs<Icrc167Result.Rejected>(request.complete(reply))
    }

    @Test
    fun `surfaces a signer error instead of pretending it is a chain`() {
        val session = TestKey.generate()
        val request = newRequest(session)
        val sent = Fragment.decode(request.authorizationUrl().substringAfter('#'))
        val id = JSONObject(sent.getValue("message")).getString("id")

        val message = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("error", JSONObject().put("code", 3001).put("message", "Action aborted"))
        val fragment = Fragment.encode(
            linkedMapOf("message" to message.toString(), "state" to sent.getValue("state")),
        )

        val result = request.complete("$callback#$fragment")

        assertIs<Icrc167Result.SignerError>(result)
        assertEquals(3001, result.code)
    }

    @Test
    fun `rejects a duplicated fragment parameter`() {
        val session = TestKey.generate()
        val request = newRequest(session)
        val sent = Fragment.decode(request.authorizationUrl().substringAfter('#'))

        // Two `state` values: a parser that keeps either one is exploitable.
        val fragment = "message=%7B%7D&state=${sent["state"]}&state=injected"
        val result = request.complete("$callback#$fragment")

        assertIs<Icrc167Result.Rejected>(result)
        // Without naming the reason this passes even if duplicates are silently resolved:
        // first-wins would fail on the id, last-wins on the state.
        assertTrue(result.reason.contains("duplicate"))
    }

    @Test
    fun `refuses to build a request with a fragment in the callback`() {
        val session = TestKey.generate()
        assertFailsWith<IllegalArgumentException> {
            Icrc167.delegationRequest(
                callback = "https://example.org/cb#already",
                sessionPublicKeyDer = session.der,
            )
        }
    }

    @Test
    fun `refuses an empty target list, which means something different from none`() {
        val session = TestKey.generate()
        assertFailsWith<IllegalArgumentException> {
            Icrc167.delegationRequest(
                callback = callback,
                sessionPublicKeyDer = session.der,
                targets = emptyList(),
            )
        }
    }
}
