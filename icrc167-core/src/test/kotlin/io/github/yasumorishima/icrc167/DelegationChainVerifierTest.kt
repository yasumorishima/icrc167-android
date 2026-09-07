package io.github.yasumorishima.icrc167

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DelegationChainVerifierTest {

    private val verifier = DelegationChainVerifier(ed25519Verifier)

    @Test
    fun `accepts a single hop chain and derives the principal from the root`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val chain = buildChain(root, listOf(session))

        val result = verifier.verify(chain, session.der, nowNanos())

        assertIs<ChainVerification.Valid>(result)
        // The caller a canister sees is the root, never the session key.
        assertEquals(Principal.selfAuthenticating(root.der), result.principal)
    }

    @Test
    fun `accepts a two hop chain, as Internet Identity returns`() {
        // II never lets a canister sign directly over our session key: it inserts an
        // ephemeral key of its own and adds a second hop to us.
        val root = TestKey.generate()
        val intermediate = TestKey.generate()
        val session = TestKey.generate()
        val chain = buildChain(root, listOf(intermediate, session))

        val result = verifier.verify(chain, session.der, nowNanos())

        assertIs<ChainVerification.Valid>(result)
        assertEquals(Principal.selfAuthenticating(root.der), result.principal)
    }

    @Test
    fun `accepts a scoped chain when the call target is listed`() {
        val target = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
        val root = TestKey.generate()
        val session = TestKey.generate()
        val chain = buildChain(root, listOf(session), targets = listOf(target))

        val result = verifier.verify(chain, session.der, nowNanos(), callTarget = target)

        assertIs<ChainVerification.Valid>(result)
    }

    @Test
    fun `rejects a tampered signature`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val chain = buildChain(root, listOf(session))

        val forged = chain.delegations[0].signature.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val tampered = DelegationChain(
            chain.publicKey,
            listOf(SignedDelegation(chain.delegations[0].delegation, forged)),
        )

        val result = verifier.verify(tampered, session.der, nowNanos())

        assertIs<ChainVerification.Invalid>(result)
        assertEquals(ChainRejection.BadSignature(0), result.reason)
    }

    @Test
    fun `rejects an expired delegation`() {
        val root = TestKey.generate()
        val session = TestKey.generate()
        val chain = buildChain(root, listOf(session), expiration = nanosFromNow(-60))

        val result = verifier.verify(chain, session.der, nowNanos())

        assertIs<ChainVerification.Invalid>(result)
        assertIs<ChainRejection.Expired>(result.reason)
    }

    @Test
    fun `rejects a chain that ends at somebody else's key`() {
        // A well-formed chain for a *different* session key must not be accepted just
        // because every signature in it checks out.
        val root = TestKey.generate()
        val someoneElse = TestKey.generate()
        val ourSession = TestKey.generate()
        val chain = buildChain(root, listOf(someoneElse))

        val result = verifier.verify(chain, ourSession.der, nowNanos())

        assertIs<ChainVerification.Invalid>(result)
        assertIs<ChainRejection.SessionKeyMismatch>(result.reason)
    }

    @Test
    fun `rejects a call to a canister outside the delegation scope`() {
        val allowed = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
        val other = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai")
        val root = TestKey.generate()
        val session = TestKey.generate()
        val chain = buildChain(root, listOf(session), targets = listOf(allowed))

        val result = verifier.verify(chain, session.der, nowNanos(), callTarget = other)

        assertIs<ChainVerification.Invalid>(result)
        assertEquals(ChainRejection.TargetNotPermitted(other), result.reason)
    }

    @Test
    fun `rejects an empty chain`() {
        val session = TestKey.generate()
        val chain = DelegationChain(TestKey.generate().der, emptyList())

        val result = verifier.verify(chain, session.der, nowNanos())

        assertIs<ChainVerification.Invalid>(result)
        assertIs<ChainRejection.Empty>(result.reason)
    }

    @Test
    fun `rejects a chain longer than the bound`() {
        val root = TestKey.generate()
        val hops = List(4) { TestKey.generate() }
        val chain = buildChain(root, hops)

        val bounded = DelegationChainVerifier(ed25519Verifier, maxChainLength = 3)
        val result = bounded.verify(chain, hops.last().der, nowNanos())

        assertIs<ChainVerification.Invalid>(result)
        assertEquals(ChainRejection.TooLong(4, 3), result.reason)
    }

    @Test
    fun `an unscoped delegation is not the same as an empty scope`() {
        // `targets: []` and no `targets` key hash differently, so they must not collide.
        val key = TestKey.generate()
        val unscoped = Delegation(key.der, BigInteger.ONE, targets = null)
        val emptyScope = Delegation(key.der, BigInteger.ONE, targets = emptyList())

        assertTrue(!unscoped.signableBytes().contentEquals(emptyScope.signableBytes()))
    }
}
