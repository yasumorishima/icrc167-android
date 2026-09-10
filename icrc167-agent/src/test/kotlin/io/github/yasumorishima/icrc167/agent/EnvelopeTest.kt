package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Delegation
import io.github.yasumorishima.icrc167.DelegationChain
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.SignedDelegation
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The envelopes, byte for byte, against fixtures a separate script produced.
 *
 * Why whole envelopes and not field-by-field assertions: a test that rebuilt the expected
 * bytes the way the implementation builds them would agree with itself no matter what it
 * emitted. The fixtures come from an independent implementation whose output mainnet accepted
 * on 2026-09-10 -- see `vectors/README.md` -- which is the only thing that makes them
 * evidence.
 */
class EnvelopeTest {

    private val agent = IcAgent(transport = Transport { _, _ -> error("this test sends nothing") })
    private val canister = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
    private val expiry = BigInteger("1757462400000000000")
    private val delegationExpiry = BigInteger("1757469600000000000")
    private val root = TestKey.counting(0)
    private val session = TestKey.counting(32)

    private fun request(identity: Identity): SignedRequest =
        agent.queryRequest(canister, "whoami", Candid.EMPTY_ARGS, identity, expiry)

    private fun chain(targets: List<Principal>? = null): DelegationChain {
        val delegation = Delegation(session.der, delegationExpiry, targets)
        return DelegationChain(
            root.der,
            listOf(SignedDelegation(delegation, root.sign(delegation.signableBytes()))),
        )
    }

    private fun fields(body: ByteArray): Map<String, CborItem> =
        checkNotNull(AgentCbor.textMap(AgentCbor.decode(body)))

    @Test
    fun `an anonymous query is the envelope mainnet answered`() {
        val built = request(AnonymousIdentity)
        assertEquals(vectorText("envelope-anonymous.hex"), built.body.toHex())
        assertFalse(fields(built.body).containsKey("sender_sig"))
    }

    @Test
    fun `a key that speaks for itself produces the captured envelope`() {
        val built = request(KeyIdentity(root.der, root.signer()))
        assertEquals(vectorText("request-id.hex"), built.requestId.toHex())
        assertEquals(vectorText("envelope-key.hex"), built.body.toHex())
    }

    @Test
    fun `a delegated identity produces the captured envelope`() {
        val built = request(DelegatedIdentity(chain(), session.signer()))
        assertEquals(vectorText("envelope-delegated.hex"), built.body.toHex())
        // The request id does not depend on who signed it, only on the content.
        assertEquals(vectorText("request-id.hex"), built.requestId.toHex())
    }

    @Test
    fun `the signature covers the request id under the ic-request separator`() {
        val built = request(DelegatedIdentity(chain(), session.signer()))
        val signature = (fields(built.body)["sender_sig"] as CborItem.Blob).bytes
        val signed = requestDomainSeparator() + built.requestId
        assertTrue(ed25519Verify(session.der, signed, signature), "the session key signs the request")
        assertFalse(ed25519Verify(root.der, signed, signature), "and the root key does not")
        assertContentEquals(
            byteArrayOf(0x0A) + "ic-request".toByteArray(),
            requestDomainSeparator(),
        )
    }

    @Test
    fun `the sender is the root of the chain, never the session key`() {
        val identity = DelegatedIdentity(chain(), session.signer())
        assertEquals(Principal.selfAuthenticating(root.der).toText(), identity.sender.toText())
        val sender = (fields(request(identity).body)["content"] as CborItem.Dict)
        val content = checkNotNull(AgentCbor.textMap(sender))
        assertContentEquals(
            Principal.selfAuthenticating(root.der).bytes,
            (content["sender"] as CborItem.Blob).bytes,
        )
    }

    @Test
    fun `targets are absent when the delegation is unscoped and present when it is not`() {
        val unscoped = delegationFields(request(DelegatedIdentity(chain(), session.signer())).body)
        assertFalse(unscoped.containsKey("targets"), "an empty targets array is a different delegation")

        val scoped = chain(targets = listOf(canister))
        val fields = delegationFields(request(DelegatedIdentity(scoped, session.signer())).body)
        val targets = (fields["targets"] as CborItem.Arr).items
        assertEquals(1, targets.size)
        assertContentEquals(canister.bytes, (targets[0] as CborItem.Blob).bytes)
    }

    private fun delegationFields(body: ByteArray): Map<String, CborItem> {
        val list = (fields(body)["sender_delegation"] as CborItem.Arr).items
        assertEquals(1, list.size)
        val entry = checkNotNull(AgentCbor.textMap(list[0]))
        return checkNotNull(AgentCbor.textMap(entry["delegation"]!!))
    }
}
