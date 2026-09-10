package io.github.yasumorishima.icrc167.demo

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.agent.AnonymousIdentity
import io.github.yasumorishima.icrc167.agent.DelegatedIdentity
import io.github.yasumorishima.icrc167.agent.IcAgent
import io.github.yasumorishima.icrc167.agent.Identity
import io.github.yasumorishima.icrc167.agent.QueryResponseVerifier
import io.github.yasumorishima.icrc167.agent.Signer
import io.github.yasumorishima.icrc167.android.AuthOutcome
import io.github.yasumorishima.icrc167.android.Icrc167Client
import io.github.yasumorishima.icrc167.android.SessionKey
import io.github.yasumorishima.icrc167.canistersig.MiraclBls
import io.github.yasumorishima.icrc167.certificate.CertificateVerifier
import io.github.yasumorishima.icrc167.crypto.StandardSignatureVerifier
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Signs in with Internet Identity, then asks a canister who it thinks is calling.
 *
 * Verifying the chain on the device only shows that the chain agrees with itself: the
 * principal comes from the root key the answer carried. The canister is the outside witness.
 * It is DFINITY's own relying party, which answers whoami with the caller it attributes the
 * request to, and its answer is checked against the node signature before it is believed.
 *
 * Two controls run beside it, because a match on its own would also fit a canister that
 * answers everyone alike: an anonymous call has to come back as 2vxsx-fae, and the same chain
 * signed with a key it does not name has to be refused by the replica.
 */
class DemoActivity : Activity() {

    private val client by lazy { Icrc167Client(this, CALLBACK_URL) }
    private val network: ExecutorService = Executors.newSingleThreadExecutor()
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply {
            textSize = 16f
            setTextIsSelectable(true)
        }
        val signIn = Button(this).apply {
            text = "Sign in with Internet Identity"
            setOnClickListener { client.launch(this@DemoActivity) }
        }
        val signOut = Button(this).apply {
            text = "Sign out"
            setOnClickListener {
                client.signOut()
                status.text = ""
                say("Signed out. The session keys are gone.")
            }
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            addView(signIn)
            addView(signOut)
            addView(status)
        }
        setContentView(ScrollView(this).apply { addView(column) })

        if (savedInstanceState != null) {
            // A rotation replays the launch intent. The attempt it answered is already spent,
            // so handling it again would only report a link that is no longer ours.
            status.text = savedInstanceState.getCharSequence(STATUS)
        } else {
            handle(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handle(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putCharSequence(STATUS, status.text)
    }

    override fun onDestroy() {
        network.shutdownNow()
        super.onDestroy()
    }

    private fun handle(intent: Intent?) {
        if (intent?.data == null) {
            say("Not signed in.")
            return
        }
        status.text = ""
        when (val outcome = client.handleRedirect(intent)) {
            is AuthOutcome.Success -> confirm(outcome)
            // Shown verbatim: this app is where a live canister signature is first checked,
            // and the reason is what says which part refused it.
            is AuthOutcome.Failed -> say("Sign-in refused: " + outcome.reason)
            AuthOutcome.NotOurs -> say("That link is not an answer to a sign-in started here.")
        }
    }

    private fun confirm(outcome: AuthOutcome.Success) {
        val key = client.activeSessionKey()
        if (key == null) {
            say("Signed in, but the session key is gone, so nothing can be signed with it.")
            return
        }
        val expected = outcome.principal.toText()
        say("Signed in. The chain names " + expected)
        say("Scope: " + (outcome.effectiveTargets?.joinToString { it.toText() } ?: "any canister"))
        say("Asking " + CANISTER.toText() + " who is calling...")

        val signed = DelegatedIdentity(outcome.chain, Signer(key::sign))
        val wrongKey = DelegatedIdentity(outcome.chain, Signer(SessionKey.generate()::sign))
        network.execute {
            val seen = ask(signed)
            report(
                if (seen == expected) {
                    "MATCH: the canister sees " + seen
                } else {
                    "NO MATCH: " + seen + " (the chain names " + expected + ")"
                },
            )
            report("Control, anonymous: " + ask(AnonymousIdentity) + " (must be 2vxsx-fae)")
            report("Control, a key the chain does not name: " + ask(wrongKey) + " (must be refused)")
        }
    }

    /** The principal the canister reports, or why there is none. Runs off the main thread. */
    private fun ask(identity: Identity): String = try {
        IcAgent().verifiedWhoami(CANISTER, identity, verifier).toText()
    } catch (e: Exception) {
        "refused: " + e.message
    }

    private fun report(line: String) = runOnUiThread { say(line) }

    private fun say(line: String) {
        status.append(line)
        status.append(System.lineSeparator())
    }

    private companion object {
        const val STATUS = "status"

        /** Listed in the origin's ii-auth-callbacks, and claimed by this app's App Link. */
        const val CALLBACK_URL = "https://callback-origin.vercel.app/icrc167-callback"

        /** DFINITY's relying-party canister. It exports whoami as a query returning the caller. */
        val CANISTER: Principal = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")

        /** Node signatures are Ed25519, and the subnet certificate is checked to the root key. */
        val verifier = QueryResponseVerifier(CertificateVerifier(MiraclBls), StandardSignatureVerifier())
    }
}
