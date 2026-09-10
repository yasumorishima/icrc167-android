package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Principal
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Replies recorded from mainnet, replayed through the parser. */
class ReplyTest {

    private val canister = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
    private val urls = ArrayList<String>()

    private fun agentAnswering(status: Int, body: ByteArray) = IcAgent(
        transport = Transport { url, _ ->
            urls.add(url)
            HttpResponse(status, body)
        },
    )

    @Test
    fun `the recorded reply is a principal`() {
        val reply = agentAnswering(200, vector("whoami-anonymous-reply.cbor"))
            .query(canister, "whoami", Candid.EMPTY_ARGS, AnonymousIdentity)
        val arg = (reply as QueryReply.Replied).arg
        assertEquals("2vxsx-fae", Candid.decodePrincipal(arg).toText())
    }

    @Test
    fun `whoami goes to the v2 query path of the canister it names`() {
        val seen = agentAnswering(200, vector("whoami-anonymous-reply.cbor"))
            .whoami(canister, AnonymousIdentity)
        assertEquals("2vxsx-fae", seen.toText())
        assertEquals(
            listOf("https://icp-api.io/api/v2/canister/kvusz-kaaaa-aaaad-aabwa-cai/query"),
            urls,
        )
    }

    @Test
    fun `the recorded rejection keeps the code the replica sent`() {
        val reply = agentAnswering(200, vector("rejected-reply.cbor"))
            .query(canister, "no_such_method_here", Candid.EMPTY_ARGS, AnonymousIdentity)
        val rejected = reply as QueryReply.Rejected
        assertEquals(BigInteger.valueOf(5), rejected.rejectCode)
        assertEquals("IC0536", rejected.errorCode)
        assertTrue(rejected.message.contains("no query method"), rejected.message)
    }

    @Test
    fun `a rejection is not silently turned into an identity`() {
        val agent = agentAnswering(200, vector("rejected-reply.cbor"))
        val failure = assertFailsWith<IcAgentException> { agent.whoami(canister, AnonymousIdentity) }
        assertTrue(failure.message!!.contains("IC0536") || failure.message!!.contains("no query method"))
    }

    @Test
    fun `a refusal from the replica arrives with its own words`() {
        // Verbatim from mainnet on 2026-09-10, for an envelope signed by the wrong key.
        val text = "Invalid signature: Invalid basic signature: Ed25519 signature could not be verified"
        val agent = agentAnswering(400, text.toByteArray())
        val failure = assertFailsWith<IcAgentException> {
            agent.query(canister, "whoami", Candid.EMPTY_ARGS, AnonymousIdentity)
        }
        assertTrue(failure.message!!.contains("400"), failure.message)
        assertTrue(failure.message!!.contains("Invalid basic signature"), failure.message)
    }

    @Test
    fun `a reply that is not one is refused rather than guessed at`() {
        val agent = agentAnswering(200, ByteArray(0))
        listOf(
            "a0",
            "a166737461747573657265706c79",
            "a266737461747573677265706c696564657265706c79a0",
            "a166737461747573646e657721",
        ).forEach { hex ->
            assertFailsWith<IcAgentException>(hex) { agent.parseReply(hex.fromHex()) }
        }
    }

    @Test
    fun `an anonymous identity signs nothing`() {
        assertNull(AnonymousIdentity.authenticate(ByteArray(32)))
        assertEquals("2vxsx-fae", AnonymousIdentity.sender.toText())
    }
}
