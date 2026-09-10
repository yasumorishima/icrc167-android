package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.Principal
import io.github.yasumorishima.icrc167.ReprHash
import io.github.yasumorishima.icrc167.canistersig.MiraclBls
import io.github.yasumorishima.icrc167.certificate.Certificate
import io.github.yasumorishima.icrc167.certificate.CertificateVerifier
import io.github.yasumorishima.icrc167.certificate.Lookup
import io.github.yasumorishima.icrc167.certificate.lookupPath
import io.github.yasumorishima.icrc167.crypto.StandardSignatureVerifier
import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Recorded exchanges from mainnet, checked all the way to the network root key.
 *
 * The BLS pairing here is the real one and the certificates are the ones the network issued,
 * so nothing is stubbed except the transport and the clock. The clock has to be: the verifier
 * refuses stale answers, and a recording is stale the moment it is a recording, so each test
 * runs it at the time the answer was signed.
 */
class ResponseVerificationTest {

    private val canister = Principal.fromText("kvusz-kaaaa-aaaad-aabwa-cai")
    private val ledger = Principal.fromText("ryjl3-tyaaa-aaaaa-aaaba-cai")
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

    /** A verifier whose idea of now is the moment the recorded answer was signed. */
    private fun verifierAt(
        exchange: QueryExchange,
        skew: BigInteger = BigInteger.ZERO,
        rootKeyRaw: ByteArray? = null,
        rootSubnetId: Principal? = QueryResponseVerifier.MAINNET_ROOT_SUBNET,
    ): QueryResponseVerifier {
        val signed = exchange.response.signatures.first().timestamp
        val certificates = if (rootKeyRaw == null) {
            CertificateVerifier(MiraclBls)
        } else {
            CertificateVerifier(MiraclBls, rootPublicKeyRaw = rootKeyRaw)
        }
        return QueryResponseVerifier(
            certificates,
            StandardSignatureVerifier(),
            rootSubnetId = rootSubnetId,
            clock = { signed + skew },
        )
    }

    private fun reasonOf(checked: ResponseVerification): String {
        assertTrue(checked is ResponseVerification.Invalid, checked.toString())
        return (checked as ResponseVerification.Invalid).reason
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
        assertEquals(
            vectorText("response-hash.hex"),
            verifierAt(exchange).coveredHash(exchange, signature).toHex(),
        )
    }

    @Test
    fun `a recorded answer verifies to the network root key`() {
        val exchange = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val checked = verifierAt(exchange).verify(canister, exchange, vector("subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Valid, checked.toString())
        assertEquals(1, (checked as ResponseVerification.Valid).signatures.size)
    }

    @Test
    fun `a rejection is signed too, and the error code is part of what is signed`() {
        val exchange = exchangeOf("rejected-request.hex", "rejected-signed-reply.cbor")
        assertEquals(vectorText("rejected-request-id.hex"), exchange.request.requestId.toHex())
        assertTrue(exchange.response.reply is QueryReply.Rejected)
        val signature = exchange.response.signatures.single()
        assertEquals(
            vectorText("rejected-response-hash.hex"),
            verifierAt(exchange).coveredHash(exchange, signature).toHex(),
        )
        val checked = verifierAt(exchange)
            .verify(canister, exchange, vector("rejected-subnet-certificate.cbor"))
        assertTrue(checked is ResponseVerification.Valid, checked.toString())
    }

    @Test
    fun `an answer from the root subnet needs no delegation, and is still bound to the canister`() {
        // The certificate here carries no delegation, so nothing names the subnet: the root
        // subnet has to be the one asked for, and it has to cover the canister. The root
        // state tree holds the node keys of every subnet, so without that binding a genuine
        // root certificate would authorise any node anywhere to answer for anything.
        val exchange = exchangeOf("root-subnet-request.hex", "root-subnet-reply.cbor")
        val certificate = vector("root-subnet-certificate.cbor")
        assertTrue(exchange.response.reply is QueryReply.Rejected)
        val checked = verifierAt(exchange).verify(ledger, exchange, certificate)
        assertTrue(checked is ResponseVerification.Valid, checked.toString())

        // The same certificate, asked about a canister on another subnet.
        assertTrue(
            reasonOf(verifierAt(exchange).verify(canister, exchange, certificate))
                .contains("does not cover"),
        )
        // And with no root subnet configured there is nothing to bind it to.
        assertTrue(
            reasonOf(verifierAt(exchange, rootSubnetId = null).verify(ledger, exchange, certificate))
                .contains("no root subnet id"),
        )
    }

    @Test
    fun `an answer that is not recent enough is refused`() {
        val exchange = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val certificate = vector("subnet-certificate.cbor")
        val tenMinutes = BigInteger.valueOf(10L * 60 * 1_000_000_000L)
        // The specification requires recency and fixes no window, so this is the one thing
        // here that is a choice rather than a measurement -- and it has to bite.
        assertTrue(
            reasonOf(verifierAt(exchange, skew = tenMinutes).verify(canister, exchange, certificate))
                .contains("recent enough"),
        )
        assertTrue(
            reasonOf(verifierAt(exchange, skew = tenMinutes.negate()).verify(canister, exchange, certificate))
                .contains("recent enough"),
        )
    }

    @Test
    fun `one byte of the answer changed, and it is no longer signed`() {
        // Inside the Candid argument, not at the end of the file: the last byte there is the
        // break of an indefinite-length map, and moving it breaks the framing instead of the
        // answer. A negative test that dies before the check it is named for proves nothing.
        val tampered = vector("signed-reply.cbor")
        val didl = tampered.toHex().indexOf("4449444c") / 2
        val at = didl + 9
        tampered[at] = (tampered[at] + 1).toByte()
        val exchange = exchangeOf("signed-request.hex", "signed-reply.cbor", reply = tampered)
        val checked = verifierAt(exchange).verify(canister, exchange, vector("subnet-certificate.cbor"))
        assertTrue(reasonOf(checked).contains("did not sign"))
    }

    @Test
    fun `the answer has to match the request it is paired with`() {
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val other = exchangeOf("rejected-request.hex", "rejected-signed-reply.cbor")
        val crossed = QueryExchange(other.request, real.response)
        val checked = verifierAt(crossed).verify(canister, crossed, vector("subnet-certificate.cbor"))
        assertTrue(reasonOf(checked).contains("did not sign"))
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
        val checked = verifierAt(swapped).verify(canister, swapped, vector("subnet-certificate.cbor"))
        assertTrue(reasonOf(checked).contains("does not have node"))
    }

    @Test
    fun `an answer nobody signed is refused`() {
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val unsigned = QueryExchange(
            real.request,
            QueryResponse(real.response.reply, emptyList(), real.response.body),
        )
        val verifier = verifierAt(real)
        val checked = verifier.verify(canister, unsigned, vector("subnet-certificate.cbor"))
        assertTrue(reasonOf(checked).contains("no signature"))
    }

    @Test
    fun `a certificate for another canister does not certify this one`() {
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        // Not on this subnet, so the delegation does not cover it.
        val elsewhere = Principal.fromText("aaaaa-aa")
        val checked = verifierAt(real).verify(elsewhere, real, vector("subnet-certificate.cbor"))
        assertTrue(reasonOf(checked).startsWith("the subnet certificate:"))
    }

    @Test
    fun `a genuine BLS key that is not the root key does not certify this subnet`() {
        // The one case only the pairing can answer. A key of the wrong shape would be turned
        // away by the decoder before any arithmetic happened, so this uses a real subnet key
        // out of the certificate itself: it decodes, it is in the subgroup, and it is not the
        // key that signed.
        val real = exchangeOf("signed-request.hex", "signed-reply.cbor")
        val checked = verifierAt(real, rootKeyRaw = subnetKeyRaw())
            .verify(canister, real, vector("subnet-certificate.cbor"))
        assertTrue(reasonOf(checked).startsWith("the subnet certificate:"))
    }

    /** The 96 raw bytes of the delegated subnet key, read out of the recorded certificate. */
    private fun subnetKeyRaw(): ByteArray {
        val outer = Certificate.fromCbor(vector("subnet-certificate.cbor"))
        val delegation = checkNotNull(outer.delegation)
        val inner = Certificate.fromCbor(delegation.certificate)
        val found = inner.tree.lookupPath(
            listOf(
                "subnet".toByteArray(Charsets.UTF_8),
                delegation.subnetId,
                "public_key".toByteArray(Charsets.UTF_8),
            ),
        )
        val der = (found as Lookup.Found).value
        return der.copyOfRange(der.size - 96, der.size)
    }
}
