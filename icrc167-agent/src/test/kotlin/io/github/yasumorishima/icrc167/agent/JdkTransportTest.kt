package io.github.yasumorishima.icrc167.agent

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The transport against a real socket, because the thing worth testing here -- that a huge
 * answer is cut off rather than read into memory -- cannot be seen with a fake.
 *
 * The server is a JDK one on loopback: no network, no dependency.
 */
class JdkTransportTest {

    private fun withServer(
        status: Int,
        body: ByteArray,
        block: (String) -> Unit,
    ) {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/api") { exchange ->
            exchange.requestBody.use { it.readBytes() }
            exchange.sendResponseHeaders(status, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        server.start()
        try {
            block("http://127.0.0.1:${server.address.port}/api")
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `carries the status and the body back`() {
        withServer(200, byteArrayOf(1, 2, 3)) { url ->
            val response = JdkTransport().post(url, byteArrayOf(9))
            assertEquals(200, response.status)
            assertEquals("010203", response.body.toHex())
        }
    }

    @Test
    fun `an error status keeps its body instead of throwing`() {
        // The replica explains a bad signature in the error body, and IcAgent quotes it.
        val text = "Invalid signature: Invalid basic signature"
        withServer(400, text.toByteArray()) { url ->
            val response = JdkTransport().post(url, byteArrayOf(9))
            assertEquals(400, response.status)
            assertEquals(text, String(response.body))
        }
    }

    @Test
    fun `a body over the ceiling is refused rather than read`() {
        withServer(200, ByteArray(100_000)) { url ->
            val failure = assertFailsWith<IcAgentException> {
                JdkTransport(maxBodyBytes = 1024).post(url, byteArrayOf(9))
            }
            assertTrue(failure.message!!.contains("ceiling"), failure.message)
        }
        // And the same body is fine when it fits.
        withServer(200, ByteArray(100_000)) { url ->
            assertEquals(100_000, JdkTransport(maxBodyBytes = 200_000).post(url, byteArrayOf(9)).body.size)
        }
    }

    @Test
    fun `a host that is not there fails as an agent error`() {
        var closedUrl = ""
        withServer(200, byteArrayOf(1)) { url -> closedUrl = url }
        val failure = assertFailsWith<IcAgentException> { JdkTransport().post(closedUrl, byteArrayOf(9)) }
        assertTrue(failure.message!!.contains("could not be reached"), failure.message)
    }
}
