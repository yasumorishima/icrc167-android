package io.github.yasumorishima.icrc167.probe

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import java.security.MessageDigest

/**
 * Reports what actually arrives on an incoming App Link.
 *
 * The interesting field is `encodedFragment`: ICRC-167 puts the entire JSON-RPC response —
 * including the delegation — after the `#`, so if Android dropped or rewrote it, the
 * transport could not be implemented on this platform at all.
 *
 * The raw fragment is logged as a SHA-256 digest as well as verbatim, because logcat lines
 * are truncated and a byte-for-byte claim cannot rest on a possibly-clipped string.
 */
class ProbeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        report("onCreate", intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // singleTask means a second link arrives here rather than in a fresh instance.
        report("onNewIntent", intent)
    }

    private fun report(source: String, intent: Intent?) {
        val data = intent?.data
        if (data == null) {
            Log.i(TAG, "$source|NO_DATA")
            return
        }
        val encodedFragment = data.encodedFragment
        if (encodedFragment == null) {
            Log.i(TAG, "$source|FRAGMENT_ABSENT|uri=$data")
            return
        }
        val bytes = encodedFragment.toByteArray(Charsets.UTF_8)
        Log.i(TAG, "$source|FRAGMENT_PRESENT|len=${bytes.size}|sha256=${sha256(bytes)}")
        Log.i(TAG, "$source|RAW|$encodedFragment")
        // `getFragment()` percent-decodes; a parser that used it would silently mangle a
        // payload containing '+' or '%'. Record both so the difference is visible.
        Log.i(TAG, "$source|DECODED|${data.fragment}")
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    private companion object {
        const val TAG = "ICRC167PROBE"
    }
}
