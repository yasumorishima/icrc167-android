package io.github.yasumorishima.icrc167.agent

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI

/**
 * The default transport: `HttpURLConnection`, which exists on the JDK and on Android, so the
 * library adds no HTTP dependency to an app that already has one.
 *
 * An app with its own client should implement [Transport] instead of routing around this.
 */
public class JdkTransport(
    private val connectTimeoutMillis: Int = 15_000,
    private val readTimeoutMillis: Int = 30_000,
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
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            HttpResponse(status, bytes)
        } catch (e: IOException) {
            throw IcAgentException("$url could not be reached: ${e.message}")
        } finally {
            connection.disconnect()
        }
    }
}
