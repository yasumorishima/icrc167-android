package io.github.yasumorishima.icrc167.agent

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI

/**
 * The default transport: `HttpURLConnection`, which exists on the JDK and on Android, so the
 * library adds no HTTP dependency to an app that already has one.
 *
 * An app with its own client should implement [Transport] instead of routing around this.
 *
 * [host] is not required to be `https`, because a local replica is served over plain HTTP and
 * refusing that would only push people to fork the file. Point it at anything else and the
 * delegation in the envelope is on the wire in the clear.
 */
public class JdkTransport(
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 30_000,
    private val maxBodyBytes: Int = FOUR_MEBIBYTES,
) : Transport {

    override fun post(url: String, body: ByteArray): HttpResponse {
        val connection = URI(url).toURL().openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        connection.doOutput = true
        connection.instanceFollowRedirects = false
        connection.setRequestProperty("Content-Type", "application/cbor")
        connection.setRequestProperty("Accept", "application/cbor")
        return try {
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status < HttpURLConnection.HTTP_BAD_REQUEST) {
                connection.inputStream
            } else {
                // Null when the replica sent no body at all; the status still has to survive.
                connection.errorStream
            }
            HttpResponse(status, stream?.use { readCapped(it) } ?: ByteArray(0))
        } catch (e: IOException) {
            throw IcAgentException("$url could not be reached: ${e.message}")
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Reads with a ceiling.
     *
     * The parser downstream is careful never to allocate more than the input it was handed --
     * which is worth nothing if the input itself is however many bytes the other end feels
     * like sending. On a phone that is an OOM, and the other end is not always the replica:
     * it is whatever answered.
     */
    private fun readCapped(stream: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        while (true) {
            val read = stream.read(chunk)
            if (read < 0) return out.toByteArray()
            if (out.size() + read > maxBodyBytes) {
                throw IcAgentException("the response is larger than the $maxBodyBytes byte ceiling")
            }
            out.write(chunk, 0, read)
        }
    }

    public companion object {
        /**
         * A bound of our own, not a protocol constant: the interface specification leaves the
         * canister response limit to its resource-limits page rather than fixing a number.
         * Comfortably above any query reply, and far below what would hurt.
         */
        public const val FOUR_MEBIBYTES: Int = 4 * 1024 * 1024
    }
}
