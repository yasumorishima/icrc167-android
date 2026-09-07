package io.github.yasumorishima.icrc167.probe

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import io.github.yasumorishima.icrc167.android.AuthOutcome
import io.github.yasumorishima.icrc167.android.Icrc167Client

/**
 * Runs a whole ICRC-167 return trip against a stand-in signer.
 *
 * Started with no data it begins an attempt and reports what it asked for. Started by an App
 * Link it completes that attempt: parses the fragment, verifies the chain and derives the
 * principal. The test harness kills the process in between, so the path being exercised is
 * the one a real device takes while the browser holds the foreground.
 */
class AuthProbeActivity : Activity() {

    private val client by lazy { Icrc167Client(this, CALLBACK_URL) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Without this, a later recreation replays the launch intent and starts a second
        // attempt, overwriting the pending one. Apps copy this shape, so get it right here.
        setIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        if (intent?.data == null) {
            val pending = client.beginAuthentication()
            val publicKey = Base64.encodeToString(pending.sessionPublicKeyDer, Base64.NO_WRAP)
            Log.i(TAG, "BEGIN|pubkey=$publicKey|id=${pending.requestId}|state=${pending.state}")
            return
        }

        when (val outcome = client.handleRedirect(intent)) {
            is AuthOutcome.Success -> {
                Log.i(TAG, "SUCCESS|principal=${outcome.principal.toText()}")
                Log.i(TAG, "SUCCESS|hops=${outcome.chain.delegations.size}|scope=${outcome.effectiveTargets}")
            }
            is AuthOutcome.Failed -> Log.i(TAG, "FAILED|${outcome.reason}")
            AuthOutcome.NotOurs -> Log.i(TAG, "NOT_OURS")
        }
    }

    companion object {
        const val TAG = "ICRC167AUTH"

        /**
         * A reserved `.invalid` host: Digital Asset Links can never verify it, so the harness
         * approves it explicitly instead. Nothing here is ever fetched over the network.
         */
        const val CALLBACK_URL = "https://icrc167-probe.invalid/auth"
    }
}
