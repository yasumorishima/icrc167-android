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
import io.github.yasumorishima.icrc167.agent.IcAgentException
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
 * signed with a key it does not name has to be refused by the replica for its signature.
 * Every line says PASS or FAIL, so nobody has to judge the output by eye.
 */
class DemoActivity : Activity() {

    private val client by lazy { Icrc167Client(this, CALLBACK_URL) }
    private val network: ExecutorService = Executors.newSingleThreadExecutor()
    private lateinit var status: TextView
    private lateinit var signIn: Button
    private lateinit var signOut: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        status = TextView(this).apply {
            textSize = 16f
            setTextIsSelectable(true)
        }
        signIn = Button(this).apply {
            text = "Sign in with Internet Identity"
            setOnClickListener { client.launch(this@DemoActivity) }
        }
        signOut = Button(this).apply {
            text = "Sign out"
            setOnClickListener {
                client.signOut()
                status.text = ""
                say("Signed out. The session keys are gone.")
            }
        }
        // The APK ships MIRACL Core, which is Apache-2.0: say so where a user of the app sees it.
        val notice = TextView(this).apply {
            textSize = 12f
            text = "Includes MIRACL Core, under the Apache License 2.0: https://github.com/miracl/core"
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
            addView(signIn)
            addView(signOut)
            addView(status)
            addView(notice)
        }
        setContentView(ScrollView(this).apply { addView(column) })

        if (savedInstanceState != null) {
            // The attempt the launch intent answered is already spent, so handling it again
            // would only report a link that is no longer ours.
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
        // Reopened from recents, Android replays the link that started us. Its attempt is long
        // spent, and reporting it as a stranger's link would only confuse.
        val fromHistory = intent != null &&
            (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0
        if (intent?.data == null || fromHistory) {
            say("Not signed in.")
            return
        }
        status.text = ""
        say("Checking the answer...")
        busy(true)
        // Checking a real chain means BLS pairings, a Keystore round trip and calls to the
        // network, none of which belong on the thread that draws the screen.
        network.execute {
            try {
                when (val outcome = client.handleRedirect(intent)) {
                    is AuthOutcome.Success -> confirm(outcome)
                    // Shown verbatim: this app is where a live canister signature is first
                    // checked, and the reason is what says which part refused it.
                    is AuthOutcome.Failed -> report("FAIL  sign-in refused: " + outcome.reason)
                    AuthOutcome.NotOurs -> report("That link is not an answer to a sign-in started here.")
                }
            } finally {
                runOnUiThread { busy(false) }
            }
        }
    }

    /**
     * A second sign-in started while this one is being checked would replace the pending
     * session key underneath it, and the check would then sign with a key the chain does not
     * name. So the buttons wait.
     */
    private fun busy(checking: Boolean) {
        signIn.isEnabled = !checking
        signOut.isEnabled = !checking
    }

    /** Runs on the network thread. */
    private fun confirm(outcome: AuthOutcome.Success) {
        val key = client.activeSessionKey()
        if (key == null) {
            report("FAIL  signed in, but the session key is gone, so nothing can be signed with it")
            return
        }
        val expected = outcome.principal.toText()
        report("Signed in. The chain names " + expected)
        report("Scope: " + (outcome.effectiveTargets?.joinToString { it.toText() } ?: "any canister"))
        report("Asking " + CANISTER.toText() + " who is calling...")

        val seen = ask(DelegatedIdentity(outcome.chain, Signer(key::sign)))
        report(verdict(seen == expected) + "the canister sees " + seen + "; the chain names " + expected)

        val anonymous = ask(AnonymousIdentity)
        report(
            verdict(anonymous == ANONYMOUS) +
                "an anonymous call is seen as " + anonymous,
        )

        report(wrongKeyControl(DelegatedIdentity(outcome.chain, Signer(SessionKey.generate()::sign))))
    }

    /** The principal the canister reports, or why there is none. */
    private fun ask(identity: Identity): String = try {
        IcAgent().verifiedWhoami(CANISTER, identity, verifier).toText()
    } catch (e: Exception) {
        "no answer (" + e.message + ")"
    }

    /**
     * Passes only when the replica refuses the request for its signature, the same test the
     * live JVM suite applies. A network failure or a bad certificate is not a pass.
     */
    private fun wrongKeyControl(identity: Identity): String = try {
        val seen = IcAgent().verifiedWhoami(CANISTER, identity, verifier).toText()
        "FAIL  a request signed by a key the chain does not name was answered, as " + seen
    } catch (e: IcAgentException) {
        val message = e.message.orEmpty()
        if (message.contains("Invalid signature")) {
            "PASS  a key the chain does not name is refused: " + message
        } else {
            "FAIL  refused, but not for the signature: " + message
        }
    } catch (e: Exception) {
        "FAIL  the wrong-key control could not run: " + e
    }

    private fun verdict(passed: Boolean): String = if (passed) "PASS  " else "FAIL  "

    private fun report(line: String) = runOnUiThread { say(line) }

    private fun say(line: String) {
        status.append(line)
        status.append(System.lineSeparator())
    }

    private companion object {
        const val STATUS = "status"

        /** Written out rather than read from the library, so the control is not the library checking itself. */
        const val ANONYMOUS = "2vxsx-fae"

        /** Listed in the origin's ii-auth-callbacks, and claimed by this app's App Link. */
        const val CALLBACK_URL = "https://callback-origin.vercel.app/icrc167-callback"

        /** DFINITY's relying-party canister. It exports whoami as a query returning the caller. */
        val CANISTER: Principal = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")

        /** Node signatures are Ed25519, and the subnet certificate is checked to the root key. */
        val verifier = QueryResponseVerifier(CertificateVerifier(MiraclBls), StandardSignatureVerifier())
    }
}
