package io.github.yasumorishima.icrc167.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.yasumorishima.icrc167.DelegationChainVerifier
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.SignatureVerifier
import io.github.yasumorishima.icrc167.crypto.StandardSignatureVerifier
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import kotlin.concurrent.thread
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The client on a real device: real preferences, the real Keystore, real Ed25519 chains.
 *
 * Each test that guards a fix has to fail against a copy of the library with the fixes
 * reverted before it is trusted; the runs are linked from the pull request that added it.
 * A test that cannot fail proves nothing, for the same reason a passing round trip proves
 * nothing: the principal comes out of the answer itself.
 */
@RunWith(AndroidJUnit4::class)
class Icrc167ClientTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val real = StandardSignatureVerifier()

    @Before
    fun clean() = reset()

    @After
    fun cleanUp() = reset()

    /** Every piece of state the client keeps, by the names the library stores it under. */
    private fun reset() {
        for (name in listOf("icrc167-pending", "icrc167-session")) {
            context.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit()
        }
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(WRAPPING_KEY_ALIAS)
    }

    private fun client(signatures: SignatureVerifier = real) = Icrc167Client(
        context,
        Callbacks.URL,
        chainVerifier = DelegationChainVerifier(signatures),
    )

    private fun link(url: String) = Intent(Intent.ACTION_VIEW, Uri.parse(url))

    private fun success(outcome: AuthOutcome?): AuthOutcome.Success =
        outcome as? AuthOutcome.Success ?: throw AssertionError("expected Success, got $outcome")

    private fun failure(outcome: AuthOutcome?): AuthOutcome.Failed =
        outcome as? AuthOutcome.Failed ?: throw AssertionError("expected Failed, got $outcome")

    @Test
    fun aValidAnswerCompletesAndBindsTheAttemptKey() {
        val client = client()
        val pending = client.beginAuthentication()
        val answer = Callbacks.answer(pending)

        val outcome = success(client.handleRedirect(link(answer.url)))

        assertEquals(
            Principal.selfAuthenticating(answer.rootPublicKeyDer).toText(),
            outcome.principal.toText(),
        )
        assertArrayEquals(pending.sessionPublicKeyDer, client.activeSessionKey()?.publicKeyDer)
    }

    /** The control for the one above: the same answer with its signature damaged. */
    @Test
    fun aTamperedSignatureIsRefused() {
        val client = client()
        val pending = client.beginAuthentication()
        val answer = Callbacks.answer(pending, corruptSignature = true)

        val outcome = failure(client.handleRedirect(link(answer.url)))

        assertTrue(outcome.reason, outcome.reason.contains("BadSignature(index=0)"))
        assertNull(client.activeSessionKey())
    }

    /**
     * Guards the attempt lock. A completion holds it while it verifies, so a second
     * beginAuthentication has to wait instead of replacing the pending key underneath it.
     * Without the lock the second begin returns at once, well inside HELD_SECONDS, and the
     * first check fails: that is the check this test rests on. The one after the release, that
     * the second attempt still completes, catches a missing lock only when the second begin
     * writes before the first completion clears the pending state, which it may not.
     */
    @Test
    fun beginningAnAttemptWaitsForACompletionInProgress() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val gate = SignatureVerifier { key, message, signature ->
            entered.countDown()
            if (!release.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) throw AssertionError("never released")
            real.verify(key, message, signature)
        }
        val first = client(gate)
        val firstPending = first.beginAuthentication()
        val firstAnswer = Callbacks.answer(firstPending)
        val firstOutcome = AtomicReference<Result<AuthOutcome>>()
        val completing = thread { firstOutcome.set(runCatching { first.handleRedirect(link(firstAnswer.url)) }) }

        val second = client()
        val secondPending = AtomicReference<Result<Icrc167Client.Pending>>()
        val begun = CountDownLatch(1)
        try {
            assertTrue("the completion never reached the verifier", entered.await(TIMEOUT_SECONDS, TimeUnit.SECONDS))
            thread {
                secondPending.set(runCatching { second.beginAuthentication() })
                begun.countDown()
            }
            assertFalse(
                "beginAuthentication returned while a completion held the attempt",
                begun.await(HELD_SECONDS, TimeUnit.SECONDS),
            )
        } finally {
            release.countDown()
            completing.join(TIMEOUT_SECONDS * 1000)
        }
        assertFalse("the first completion never finished", completing.isAlive)
        assertTrue("the second attempt never began", begun.await(TIMEOUT_SECONDS, TimeUnit.SECONDS))

        success(firstOutcome.get().getOrThrow())
        assertArrayEquals(firstPending.sessionPublicKeyDer, first.activeSessionKey()?.publicKeyDer)

        val secondBegun = secondPending.get().getOrThrow()
        success(second.handleRedirect(link(Callbacks.answer(secondBegun).url)))
        assertArrayEquals(secondBegun.sessionPublicKeyDer, second.activeSessionKey()?.publicKeyDer)
    }

    /**
     * Guards promotion of the key the chain was verified against. The verifier swaps the
     * pending key in the store mid-completion; the key that becomes active must still be the
     * one the chain names. Reading the pending slot again at promotion would pick the swap.
     */
    @Test
    fun theKeyThatBecomesActiveIsTheOneTheChainWasVerifiedAgainst() {
        val swapped = AtomicReference<ByteArray>()
        val swapping = SignatureVerifier { key, message, signature ->
            if (swapped.get() == null) swapped.set(SessionKeyStore(context).beginAttempt().publicKeyDer)
            real.verify(key, message, signature)
        }
        val client = client(swapping)
        val pending = client.beginAuthentication()

        success(client.handleRedirect(link(Callbacks.answer(pending).url)))

        val active = client.activeSessionKey()?.publicKeyDer
        assertArrayEquals(pending.sessionPublicKeyDer, active)
        assertFalse("the swapped-in key became active", active.contentEquals(swapped.get()))
    }

    /** Guards the verifier guard: a verifier that throws is a refusal, not a crash, and the attempt is gone. */
    @Test
    fun aVerifierThatThrowsRefusesAndAbandonsTheAttempt() {
        val calls = AtomicInteger()
        val throwing = SignatureVerifier { _, _, _ ->
            calls.incrementAndGet()
            throw IllegalStateException("the verifier broke")
        }
        val client = client(throwing)
        val answer = Callbacks.answer(client.beginAuthentication())

        val outcome = failure(client.handleRedirect(link(answer.url)))

        assertTrue(outcome.reason, outcome.reason.startsWith("chain could not be checked: "))
        assertTrue(outcome.reason, outcome.reason.contains("the verifier broke"))
        assertEquals(1, calls.get())
        assertEquals(AuthOutcome.NotOurs, client.handleRedirect(link(answer.url)))
        assertEquals("a spent attempt was checked again", 1, calls.get())
        assertNull(SessionKeyStore(context).pending())
    }

    /**
     * Guards the promotion failure path. The Keystore key that wraps session keys is replaced,
     * mid-completion, by one that may only decrypt, so storing the verified key has to fail.
     * The answer must be a refusal with nothing left behind, never a Success with no active key.
     */
    @Test
    fun aKeyThatCannotBeStoredIsARefusalNotASuccess() {
        val refusal = AtomicReference<Throwable>()
        val breaking = SignatureVerifier { key, message, signature ->
            refusal.set(replaceWrappingKeyWithOneThatCannotEncrypt())
            real.verify(key, message, signature)
        }
        val client = client(breaking)
        val answer = Callbacks.answer(client.beginAuthentication())

        val outcome = failure(client.handleRedirect(link(answer.url)))

        assertTrue(outcome.reason, outcome.reason.startsWith("could not keep the session key: "))
        // A null from reading the pending slot again would land in this same refusal. This one
        // has to come from the Keystore refusing to store the key.
        assertFalse(outcome.reason, outcome.reason.contains("NullPointerException"))
        // And positively: the refusal carries the failure the Keystore gave when asked directly.
        assertTrue(outcome.reason, outcome.reason.contains(refusal.get().javaClass.name))
        assertEquals(AuthOutcome.NotOurs, client.handleRedirect(link(answer.url)))
        assertNull(SessionKeyStore(context).pending())
        assertNull(client.activeSessionKey())
    }

    /**
     * Relies on the Keystore enforcing a key's purposes, and checks that it does before the
     * test leans on it: if a decrypt-only key could encrypt, the test would prove nothing. The
     * check throws an Error, which the client does not catch, so it cannot pass for a refusal.
     * It returns what the Keystore threw, so the test can look for that same failure.
     */
    private fun replaceWrappingKeyWithOneThatCannotEncrypt(): Throwable {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.deleteEntry(WRAPPING_KEY_ALIAS)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(WRAPPING_KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        val key = generator.generateKey()
        return runCatching {
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }.doFinal(ByteArray(1))
        }.exceptionOrNull()
            ?: throw AssertionError("the Keystore let a decrypt-only key encrypt; this test cannot run")
    }

    private companion object {
        /** SessionKeyStore's alias, repeated here so the test can break it on purpose. */
        const val WRAPPING_KEY_ALIAS = "icrc167-session-wrapping-key"
        const val TIMEOUT_SECONDS = 10L
        /** Long enough that an unlocked begin, one Keystore encryption and two preference writes, returns well inside it. */
        const val HELD_SECONDS = 5L
    }
}
