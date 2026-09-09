package io.github.yasumorishima.icrc167

import kotlin.test.Test
import kotlin.test.assertEquals

class CompositeSignatureVerifierTest {

    private fun always(check: SignatureCheck) = SignatureVerifier { _, _, _ -> check }

    private fun recording(check: SignatureCheck, calls: MutableList<String>, name: String) =
        SignatureVerifier { _, _, _ ->
            calls.add(name)
            check
        }

    @Test
    fun `uses the first verifier that recognises the scheme`() {
        val calls = mutableListOf<String>()
        val composite = CompositeSignatureVerifier(
            recording(SignatureCheck.UNSUPPORTED_KEY, calls, "first"),
            recording(SignatureCheck.VALID, calls, "second"),
            recording(SignatureCheck.VALID, calls, "third"),
        )

        assertEquals(SignatureCheck.VALID, composite.verify(ByteArray(0), ByteArray(0), ByteArray(0)))
        assertEquals(listOf("first", "second"), calls)
    }

    /**
     * The important one. A verifier that recognised the key and rejected the signature has
     * spoken; asking the next one would turn any disagreement between two verifiers into an
     * accept, which is exactly backwards.
     */
    @Test
    fun `a rejection ends the search`() {
        val calls = mutableListOf<String>()
        val composite = CompositeSignatureVerifier(
            recording(SignatureCheck.INVALID, calls, "first"),
            recording(SignatureCheck.VALID, calls, "second"),
        )

        assertEquals(SignatureCheck.INVALID, composite.verify(ByteArray(0), ByteArray(0), ByteArray(0)))
        assertEquals(listOf("first"), calls)
    }

    @Test
    fun `reports an unsupported key when nobody recognises it`() {
        val composite = CompositeSignatureVerifier(
            always(SignatureCheck.UNSUPPORTED_KEY),
            always(SignatureCheck.UNSUPPORTED_KEY),
        )
        assertEquals(
            SignatureCheck.UNSUPPORTED_KEY,
            composite.verify(ByteArray(0), ByteArray(0), ByteArray(0)),
        )
    }

    @Test
    fun `an empty composite recognises nothing`() {
        assertEquals(
            SignatureCheck.UNSUPPORTED_KEY,
            CompositeSignatureVerifier().verify(ByteArray(0), ByteArray(0), ByteArray(0)),
        )
    }
}
