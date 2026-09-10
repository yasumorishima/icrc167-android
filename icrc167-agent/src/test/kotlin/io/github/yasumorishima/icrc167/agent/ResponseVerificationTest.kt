package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.ReprHash
import io.github.yasumorishima.icrc167.canistersig.MiraclBls
import io.github.yasumorishima.icrc167.certificate.CertificateVerifier
import io.github.yasumorishima.icrc167.crypto.StandardSignatureVerifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Recorded exchanges from mainnet, checked all the way to the network root key.
 *
 * The BLS pairing here is the real one and the certificate is the one the network issued, so
 * nothing in this file is stubbed except the transport. The signature over a certificate does
 * not expire, so a recording keeps working.
 */
class ResponseVerificationTest {

    private val canister = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
    private val verifier = QueryResponseVerifier(
        CertificateVerifier(MiraclBls),
        StandardSignatureVerifier(),
    )
    private val offline = IcAgent(transport = Transport { _, _ -> error("this test sends nothing") })

    private fun exchangeOf(
        requestVector: String,
        replyVector: String,
        reply: ByteArray? = null,
    ): QueryExchange {
        val envelope = vectorText(requestVector).fromHex()
        val body = checkNotNull(AgentCbor.textMap(AgentCbor.decode(envelope)))
        val content = body["content"] as CborItem.Dict
        val requestId = ReprHash.ofMap(content.toReprFields())
        val response = offline.parseResponse(reply ?: vector(replyVector))
        return QueryExchange(SignedRequest(requestId, envelope), response)
    }

    @Test
    fun `the request id is the one an independent implementation computed`() {
        val exchange = exchangeOf("signed-request.hex", "signed-reply.cbor")
        assertEquals(vectorText("signed-request-id.hex"), exchange.request.requestId.toHex())
    }

    @Test
    fun `the digest the node signed is the one an independent implementation computed`() {
        val exchange = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val signature = exchange.response.signatures.single()
        assertEquals(vectorText("response-hash.hex"), verifier.coveredHash(exchange, signature).toHex())
    }

    @Test
    fun `a recorded answer verifies to the network root key`() {
        val exchange = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val checked = verifier.verify(canister, exchange, vector("subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Valid, checked.toString())
        val valid = checked as ResponseVerification.Valid
        assertEquals(exchange.response.signatures.single().nodeId.toText(), valid.nodeId.toText())
    }

    @Test
    fun `a rejection is signed too, and the error code is part of what is signed`() {
        val exchange = exchangeOf("rejected-request.hex", "rejected-signed-reply.cbor")
        assertEquals(vectorText("rejected-request-id.hex"), exchange.request.requestId.toHex())
        assertTrue(exchange.response.reply is QueryReply.Rejected)
        val signature = exchange.response.signatures.single()
        assertEquals(
            vectorText("rejected-response-hash.hex"),
            verifier.coveredHash(exchange, signature).toHex(),
        )
        val checked = verifier.verify(canister, exchange, vector("rejected-subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Valid, checked.toString())
    }

    @Test
    fun `one byte of the answer changed, and it is no longer signed`() {
        // The last byte of the reply argument is the principal itself.
        val tampered = vector("signed-reply.cbor")
        val at = tampered.size - 1
        tampered[at] = (tampered[at] + 1).toByte()
        val exchange = exchangeOf("signed-request.hex", "signed-reply.cbor", reply = tampered)
        val checked = verifier.verify(canister, exchange, vector("subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Invalid, checked.toString())
        assertTrue((checked as ResponseVerification.Invalid).reason.contains("did not sign"))
    }

    @Test
    fun `the answer has to match the request it is paired with`() {
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val other = exchangeOf("rejected-request.hex", "rejected-signed-reply.cbor")
        // The right answer under the wrong request id: the covered hash carries the id.
        val crossed = QueryExchange(other.request, real.response)
        val checked = verifier.verify(canister, crossed, vector("subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Invalid, checked.toString())
    }

    @Test
    fun `a node the subnet does not have is refused`() {
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val signature = real.response.signatures.single()
        val stranger = NodeSignature(
            signature.timestamp,
            signature.signature,
            Principal.selfAuthenticating(ByteArray(32)),
        )
        val swapped = QueryExchange(
            real.request,
            QueryResponse(real.response.reply, listOf(stranger), real.response.body),
        )
        val checked = verifier.verify(canister, swapped, vector("subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Invalid, checked.toString())
        assertTrue((checked as ResponseVerification.Invalid).reason.contains("does not have node"))
    }

    @Test
    fun `an answer nobody signed is refused`() {
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val unsigned = QueryExchange(
            real.request,
            QueryResponse(real.response.reply, emptyList(), real.response.body),
        )
        val checked = verifier.verify(canister, unsigned, vector("subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Invalid, checked.toString())
        assertTrue((checked as ResponseVerification.Invalid).reason.contains("no signature"))
    }

    @Test
    fun `a certificate for another canister does not certify this one`() {
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        // The management canister is not on this subnet, so the delegation does not cover it.
        val elsewhere = Principal.fromText("aaaaa-aa")
        val checked = verifier.verify(elsewhere, real, vector("subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Invalid, checked.toString())
    }
}
