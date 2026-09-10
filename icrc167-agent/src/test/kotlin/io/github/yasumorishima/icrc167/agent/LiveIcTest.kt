package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Delegation
import io.github.yasumorishima.icrc167.DelegationChain
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.SignedDelegation
import io.github.yasumorishima.icrc167.systemNanos
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.condition.EnabledIfSystemProperty

/**
 * The round trip itself, against mainnet. Run with `-Dicrc167.live=1`; otherwise skipped.
 *
 * Everything else in this module measures bytes against fixtures, which cannot tell whether
 * the network still agrees. This can, and it is the only test here that would notice the IC
 * changing its mind about the wire format. It needs no Internet Identity: any Ed25519 key may
 * delegate, so the chain in the third case is one this test builds and signs itself.
 */
@EnabledIfSystemProperty(named = "icrc167.live", matches = ".+")
class LiveIcTest {

    /** DFINITY runs this relying party; it exports `whoami`. */
    private val canister = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
    private val agent = IcAgent()

    private fun tenMinutes(): BigInteger =
        systemNanos() + BigInteger.valueOf(10L * 60 * 1_000_000_000L)

    private fun chainTo(root: TestKey, session: TestKey): DelegationChain {
        val delegation = Delegation(session.der, tenMinutes())
        return DelegationChain(
            root.der,
            listOf(SignedDelegation(delegation, root.sign(delegation.signableBytes()))),
        )
    }

    @Test
    fun `an anonymous caller is the anonymous principal`() {
        assertEquals("2vxsx-fae", agent.whoami(canister, AnonymousIdentity).toText())
    }

    @Test
    fun `a key is seen as its own self-authenticating principal`() {
        val key = TestKey.random()
        val expected = Principal.selfAuthenticating(key.der)
        assertEquals(expected.toText(), agent.whoami(canister, KeyIdentity(key.der, key.signer())).toText())
    }

    @Test
    fun `a delegated session key is seen as the identity that delegated to it`() {
        val root = TestKey.random()
        val session = TestKey.random()
        val identity = DelegatedIdentity(chainTo(root, session), session.signer())
        val seen = agent.whoami(canister, identity)
        assertEquals(Principal.selfAuthenticating(root.der).toText(), seen.toText())
        assertEquals(identity.sender.toText(), seen.toText())
    }

    @Test
    fun `the network refuses a chain whose request was signed by the wrong key`() {
        val root = TestKey.random()
        val session = TestKey.random()
        // The chain says the session key may act; the request is signed by the root anyway.
        val identity = DelegatedIdentity(chainTo(root, session), root.signer())
        val failure = assertFailsWith<IcAgentException> { agent.whoami(canister, identity) }
        assertTrue(failure.message!!.contains("Invalid signature"), failure.message)
    }
}
