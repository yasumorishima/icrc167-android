package io.github.yasumorishima.icrc167

import java.math.BigInteger
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.json.JSONArray
import org.json.JSONObject

/**
 * What the signer is allowed to answer, and what it is not.
 *
 * ICRC-34 lets a signer hand back an ordinary relying-party delegation even when targets were
 * requested — it does that when it cannot establish trust for the target canisters. So an
 * unscoped answer is a legitimate outcome that changes the principal, while an answer scoped
 * *wider* than the request is authority nobody asked for.
 */
class Icrc167ScopeTest {

    private val callback = "https://example.org/icrc167-callback"
    private val canisterA = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
    private val canisterB = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai")

    private fun request(session: TestKey, targets: List<Principal>? = null) =
        Icrc167.delegationRequest(
            callback = callback,
            sessionPublicKeyDer = session.der,
            targets = targets,
        )

    private fun reply(
        request: Icrc167AuthRequest,
        root: TestKey,
        session: TestKey,
        replyTargets: List<Principal>? = null,
        expiration: BigInteger = nanosFromNow(3600),
        jsonrpc: String = "2.0",
        duplicateInBatch: Boolean = false,
    ): String {
        val sent = Fragment.decode(request.authorizationUrl().substringAfter('#'))
        val id = JSONObject(sent.getValue("message")).getString("id")

        val delegation = Delegation(session.der, expiration, replyTargets)
        val hop = JSONObject()
            .put(
                "delegation",
                JSONObject()
                    .put("pubkey", b64(session.der))
                    .put("expiration", expiration.toString())
                    .apply {
                        if (replyTargets != null) {
                            put("targets", JSONArray(replyTargets.map { it.toText() }))
                        }
                    },
            )
            .put("signature", b64(root.sign(delegation.signableBytes())))

        val response = JSONObject()
            .put("jsonrpc", jsonrpc)
            .put("id", id)
            .put(
                "result",
                JSONObject()
                    .put("publicKey", b64(root.der))
                    .put("signerDelegation", JSONArray().put(hop)),
            )

        val message = if (duplicateInBatch) {
            JSONArray().put(response).put(response).toString()
        } else {
            response.toString()
        }
        val fragment = Fragment.encode(
            linkedMapOf("message" to message, "state" to sent.getValue("state")),
        )
        return "$callback#$fragment"
    }

    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    @Test
    fun `refuses a scope wider than the one requested`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val req = request(session, targets = listOf(canisterA))

        val result = req.complete(reply(req, root, session, replyTargets = listOf(canisterA, canisterB)))

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("scope"))
    }

    @Test
    fun `accepts the requested scope and reports it`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val req = request(session, targets = listOf(canisterA, canisterB))

        val result = req.complete(reply(req, root, session, replyTargets = listOf(canisterA)))

        assertIs<Icrc167Result.Authenticated>(result)
        assertEquals(listOf(canisterA), result.effectiveTargets)
    }

    @Test
    fun `reports an unscoped answer to a scoped request instead of refusing it`() {
        // Legitimate under ICRC-34, but the principal differs from an account delegation,
        // so the caller has to be able to see which one it got.
        val root = TestKey.generate()
        val session = TestKey.generate()
        val req = request(session, targets = listOf(canisterA))

        val result = req.complete(reply(req, root, session, replyTargets = null))

        assertIs<Icrc167Result.Authenticated>(result)
        assertNull(result.effectiveTargets)
    }

    @Test
    fun `refuses a delegation that outlives the requested lifetime`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val req = request(session)

        val thirtyDays = BigInteger.valueOf(30L * 24 * 60 * 60 * 1_000_000_000)
        val result = req.complete(
            reply(req, root, session, expiration = nowNanos().add(thirtyDays)),
        )

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("maxTimeToLive"))
    }

    @Test
    fun `refuses a batch carrying two answers to the same request`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val req = request(session)

        val result = req.complete(reply(req, root, session, duplicateInBatch = true))

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("multiple"))
    }

    @Test
    fun `refuses a response that is not JSON-RPC 2 point 0`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val req = request(session)

        val result = req.complete(reply(req, root, session, jsonrpc = "1.0"))

        assertIs<Icrc167Result.Rejected>(result)
        assertTrue(result.reason.contains("JSON-RPC"))
    }

    @Test
    fun `refuses an http signer URL`() {
        // Over http anyone on the path can inject script into the signer page, read the
        // state out of location.hash and answer with a chain for an identity of their choice.
        val session = TestKey.generate()
        assertFailsWith<IllegalArgumentException> {
            Icrc167.delegationRequest(
                callback = callback,
                sessionPublicKeyDer = session.der,
                signerUrl = "http://id.ai/authorize",
            )
        }
    }

    @Test
    fun `matches the callback host case-insensitively but the path exactly`() {
        val root = TestKey.generate()
        val session = TestKey.generate()

        val upperHost = request(session)
        val fromUpperHost = reply(upperHost, root, session)
            .replace("https://example.org/", "https://EXAMPLE.ORG/")
        assertIs<Icrc167Result.Authenticated>(upperHost.complete(fromUpperHost))

        val upperPath = request(session)
        val fromUpperPath = reply(upperPath, root, session)
            .replace("/icrc167-callback#", "/ICRC167-CALLBACK#")
        assertIs<Icrc167Result.Rejected>(upperPath.complete(fromUpperPath))
    }
}
