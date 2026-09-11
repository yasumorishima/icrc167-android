package io.github.yasumorishima.icrc167.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import io.github.yasumorishima.icrc167.ChainVerification
import io.github.yasumorishima.icrc167.CompositeSignatureVerifier
import io.github.yasumorishima.icrc167.DelegationChain
import io.github.yasumorishima.icrc167.DelegationChainVerifier
import io.github.yasumorishima.icrc167.Icrc167
import io.github.yasumorishima.icrc167.Icrc167Result
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.canistersig.CanisterSignatureVerifier
import io.github.yasumorishima.icrc167.crypto.StandardSignatureVerifier
import io.github.yasumorishima.icrc167.systemNanos
import java.math.BigInteger

/** What came back from an authentication attempt. */
public sealed interface AuthOutcome {
    public data class Success(
        val principal: Principal,
        val chain: DelegationChain,
        val effectiveTargets: List<Principal>?,
    ) : AuthOutcome

    /** The link was ours but did not survive validation. */
    public data class Failed(val reason: String) : AuthOutcome

    /** An App Link that is not an answer to a pending attempt. Not an error. */
    public object NotOurs : AuthOutcome
}

/**
 * Drives an ICRC-167 sign-in from an Android app.
 *
 * The authorisation page is opened in a Custom Tab rather than a WebView, because the passkey
 * and any existing Internet Identity session live in the user's browser and a WebView can see
 * neither. The answer comes back as a verified App Link, which is why [callbackUrl] must be a
 * host this app owns through Digital Asset Links.
 *
 * Safe to call from any thread of one process. Starting an attempt and completing one are
 * serialised across the process, so there is one attempt at a time whatever callback URL a
 * client was built with: both read and write the pending attempt and its session key, and a
 * new attempt landing in the middle of a completion would bind the chain to the wrong key.
 * Nothing coordinates separate processes.
 */
public class Icrc167Client(
    context: Context,
    private val callbackUrl: String,
    private val signerUrl: String = Icrc167.INTERNET_IDENTITY_URL,
    private val maxTimeToLiveNanos: BigInteger = Icrc167.EIGHT_HOURS_NANOS,
    // Both schemes, because a real chain needs both: Internet Identity signs the root hop
    // with a canister signature and the rest with WebCrypto keys. The standard verifier on
    // its own answers UNSUPPORTED_KEY at the root, which refused every genuine sign-in.
    private val chainVerifier: DelegationChainVerifier = DelegationChainVerifier(
        CompositeSignatureVerifier(StandardSignatureVerifier(), CanisterSignatureVerifier()),
    ),
) {
    private val application = context.applicationContext
    private val keys = SessionKeyStore(application)
    private val pending =
        application.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    /**
     * A started attempt. The identifiers are exposed because an app that opens the browser
     * itself, or that wants to log what it asked for, otherwise has no way to see them.
     */
    public class Pending internal constructor(
        public val authorizationUrl: String,
        public val requestId: String,
        public val state: String,
        public val sessionPublicKeyDer: ByteArray,
    )

    /** The key a completed sign-in is bound to, for signing calls to canisters. */
    public fun activeSessionKey(): SessionKey? = keys.active()

    /**
     * Starts an attempt and returns the URL to open. Prefer [launch] unless the app wants to
     * open the browser itself. It waits while another attempt is being completed, which for a
     * real chain means BLS pairings; see [handleRedirect].
     */
    public fun beginAuthentication(targets: List<Principal>? = null): Pending =
        synchronized(ATTEMPT_LOCK) { startAttempt(targets) }

    private fun startAttempt(targets: List<Principal>?): Pending {
        // A fresh key every time: presenting one public key to a signer twice would make two
        // sign-ins linkable by the key alone. It only replaces the active key on success.
        val key = keys.beginAttempt()
        val request = Icrc167.delegationRequest(
            callback = callbackUrl,
            sessionPublicKeyDer = key.publicKeyDer,
            signerUrl = signerUrl,
            maxTimeToLiveNanos = maxTimeToLiveNanos,
            targets = targets,
        )
        // The browser holds the foreground for as long as the user takes to authenticate,
        // so this attempt has to survive us being reclaimed in the meantime.
        pending.edit()
            .putString(PENDING_ID, request.requestId)
            .putString(PENDING_STATE, request.state)
            .putString(PENDING_TARGETS, targets?.joinToString(",") { it.toText() })
            .putLong(PENDING_STARTED_AT, System.currentTimeMillis())
            .apply()
        return Pending(
            authorizationUrl = request.authorizationUrl(),
            requestId = request.requestId,
            state = request.state,
            sessionPublicKeyDer = key.publicKeyDer,
        )
    }

    /**
     * Starts an attempt and opens it in a Custom Tab. Like [beginAuthentication], it waits
     * while another attempt is being completed.
     */
    public fun launch(context: Context, targets: List<Principal>? = null) {
        val started = beginAuthentication(targets)
        CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
            .launchUrl(context, Uri.parse(started.authorizationUrl))
    }

    /**
     * Feed this every incoming `ACTION_VIEW` intent; it ignores links that are not ours. It
     * verifies the chain, which for a real Internet Identity chain means BLS pairings, and holds
     * the attempt lock while it does, so call it off the main thread.
     */
    public fun handleRedirect(intent: Intent, nowNanos: BigInteger = systemNanos()): AuthOutcome =
        synchronized(ATTEMPT_LOCK) { completeAttempt(intent, nowNanos) }

    private fun completeAttempt(intent: Intent, nowNanos: BigInteger): AuthOutcome {
        val uri = intent.data ?: return AuthOutcome.NotOurs

        // Read the *encoded* fragment. Uri.getFragment() percent-decodes the whole thing, so
        // an encoded '&' inside the payload turns into a separator and invents a parameter
        // that was never sent. Measured on a real device; see the fragment probe.
        val encodedFragment = uri.encodedFragment ?: return AuthOutcome.NotOurs
        val base = uri.buildUpon().encodedFragment(null).build().toString()

        // A link to some other part of the app is not a failed sign-in.
        if (!looksLikeOurCallback(base)) return AuthOutcome.NotOurs

        val requestId = pending.getString(PENDING_ID, null) ?: return AuthOutcome.NotOurs
        val state = pending.getString(PENDING_STATE, null) ?: return AuthOutcome.NotOurs

        // An attempt nobody ever answered would otherwise sit there forever, and every later
        // link would be judged against it.
        val startedAt = pending.getLong(PENDING_STARTED_AT, 0L)
        if (startedAt > 0 && System.currentTimeMillis() - startedAt > attemptLifetimeMillis()) {
            abandonAttempt()
            return AuthOutcome.NotOurs
        }

        val key = keys.pending() ?: run {
            // Nothing can ever complete this attempt, so do not keep judging links against it.
            abandonAttempt()
            return AuthOutcome.Failed("the session key for this attempt is gone")
        }

        val targets = pending.getString(PENDING_TARGETS, null)
            ?.split(",")
            ?.filter { it.isNotEmpty() }
            ?.map { Principal.fromText(it) }

        val request = Icrc167.restoreRequest(
            callback = callbackUrl,
            sessionPublicKeyDer = key.publicKeyDer,
            requestId = requestId,
            state = state,
            signerUrl = signerUrl,
            maxTimeToLiveNanos = maxTimeToLiveNanos,
            targets = targets,
        )

        return when (val result = request.complete("$base#$encodedFragment", nowNanos)) {
            // Deliberately keeps the attempt alive: a forged or stale callback must not be
            // able to burn a sign-in the user is still in the middle of.
            is Icrc167Result.Rejected -> AuthOutcome.Failed(result.reason)

            is Icrc167Result.SignerError -> {
                abandonAttempt()
                AuthOutcome.Failed("signer returned ${result.code}: ${result.message}")
            }

            is Icrc167Result.Authenticated -> {
                // The chain arrives from outside. A verifier that throws on input it did not
                // expect must not take the app down with it: that is a refusal like any other.
                val verification = try {
                    chainVerifier.verify(result.chain, key.publicKeyDer, nowNanos)
                } catch (e: Exception) {
                    abandonAttempt()
                    return AuthOutcome.Failed("chain could not be checked: " + e)
                }
                when (verification) {
                    is ChainVerification.Invalid -> {
                        abandonAttempt()
                        AuthOutcome.Failed("chain rejected: ${verification.reason}")
                    }
                    is ChainVerification.Valid -> {
                        // The key the chain was just verified against, not a second read of the
                        // pending slot, which can fail or find a different key.
                        try {
                            keys.promote(key)
                        } catch (e: Exception) {
                            abandonAttempt()
                            return AuthOutcome.Failed("could not keep the session key: " + e)
                        }
                        clearPending()
                        AuthOutcome.Success(
                            principal = verification.principal,
                            chain = result.chain,
                            effectiveTargets = result.effectiveTargets,
                        )
                    }
                }
            }
        }
    }

    /** Forgets the pending attempt and every session key, e.g. on sign-out. */
    public fun signOut(): Unit = synchronized(ATTEMPT_LOCK) {
        clearPending()
        keys.clear()
    }

    private fun abandonAttempt() {
        clearPending()
        keys.discardPending()
    }

    private fun clearPending() {
        pending.edit()
            .remove(PENDING_ID)
            .remove(PENDING_STATE)
            .remove(PENDING_TARGETS)
            .remove(PENDING_STARTED_AT)
            .apply()
    }

    /**
     * A cheap routing check only. The authoritative comparison happens inside `complete`,
     * which is byte-exact on the path; this exists so an unrelated deep link is reported as
     * [AuthOutcome.NotOurs] rather than as a failed sign-in.
     */
    private fun looksLikeOurCallback(base: String): Boolean =
        normaliseOrigin(base) == normaliseOrigin(callbackUrl)

    private fun normaliseOrigin(url: String): String {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return url
        val authorityEnd = url.indexOf('/', schemeEnd + 3).let { if (it < 0) url.length else it }
        return url.substring(0, authorityEnd).lowercase() + url.substring(authorityEnd)
    }

    /** A delegation cannot outlive its own lifetime, so neither can an attempt for one. */
    private fun attemptLifetimeMillis(): Long =
        maxTimeToLiveNanos.divide(BigInteger.valueOf(1_000_000)).toLong()

    private companion object {
        /**
         * One lock for the process, not one per client. The attempt lives in preferences and
         * in the key store, which every client in the process shares, and an activity that is
         * recreated builds a new client while the old one may still be completing.
         */
        val ATTEMPT_LOCK = Any()

        const val PREFERENCES = "icrc167-pending"
        const val PENDING_ID = "request-id"
        const val PENDING_STATE = "state"
        const val PENDING_TARGETS = "targets"
        const val PENDING_STARTED_AT = "started-at"
    }
}
