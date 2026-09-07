package io.github.yasumorishima.icrc167

import java.net.URLDecoder
import java.net.URLEncoder

/**
 * ICRC-167 carries both the request and the response in the URL *hash fragment*, encoded as
 * `application/x-www-form-urlencoded`.
 *
 * The fragment is used precisely because it is not sent to any server, so the JSON-RPC
 * payload — which may contain a delegation — never reaches the relying party's or the
 * signer's backend, nor any intermediary that logs request lines.
 */
internal object Fragment {

    fun encode(params: Map<String, String>): String =
        params.entries.joinToString("&") { (key, value) ->
            "${URLEncoder.encode(key, "UTF-8")}=${URLEncoder.encode(value, "UTF-8")}"
        }

    fun decode(fragment: String): Map<String, String> {
        val body = fragment.removePrefix("#")
        if (body.isEmpty()) return emptyMap()

        val params = LinkedHashMap<String, String>()
        for (pair in body.split("&")) {
            if (pair.isEmpty()) continue
            val separator = pair.indexOf('=')
            // A parameter without '=' carries no value; ICRC-167 defines none, so drop it
            // rather than inventing an empty string for it.
            if (separator < 0) continue
            val key = URLDecoder.decode(pair.substring(0, separator), "UTF-8")
            val value = URLDecoder.decode(pair.substring(separator + 1), "UTF-8")
            // Reject rather than pick a winner. A duplicated `state` or `message` is how an
            // attacker probes for a parser that keeps the first or the last one; there is no
            // legitimate reason for one, so fail closed.
            require(!params.containsKey(key)) { "duplicate fragment parameter '$key'" }
            params[key] = value
        }
        return params
    }
}
