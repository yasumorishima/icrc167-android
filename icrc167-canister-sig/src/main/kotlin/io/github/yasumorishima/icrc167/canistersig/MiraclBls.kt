package io.github.yasumorishima.icrc167.canistersig

import io.github.yasumorishima.icrc167.certificate.BlsSignatureVerifier
import org.miracl.core.BLS12381.BIG
import org.miracl.core.BLS12381.CONFIG_BIG
import org.miracl.core.BLS12381.CONFIG_CURVE
import org.miracl.core.BLS12381.DBIG
import org.miracl.core.BLS12381.ECP
import org.miracl.core.BLS12381.ECP2
import org.miracl.core.BLS12381.FP
import org.miracl.core.BLS12381.FP2
import org.miracl.core.BLS12381.PAIR
import org.miracl.core.BLS12381.ROM
import org.miracl.core.HMAC

/**
 * BLS12-381 signature verification for IC certificates, over MIRACL Core.
 *
 * Ciphersuite `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`: signatures are points of G1 (48
 * bytes compressed), public keys are points of G2 (96 bytes compressed), and the message is
 * mapped to G1 with SSWU. That is what the IC interface specification names, and it is the
 * opposite arrangement from most Ethereum-side BLS code.
 *
 * **MIRACL's own `BLS` class cannot be used for this.** Its `bls_hash_to_point` hard-codes the
 * domain separation tag `BLS_SIG_BLS12381G1_XMD:SHA-256_SVDW_RO_NUL_`, which differs from the
 * IC's in the map name. The tag is hashed into the message expansion, so the point that comes
 * out is a different point and every genuine signature would fail to verify. The map itself is
 * SSWU either way — `config64.py` gives BLS12381 an isogeny degree of 11 for G1, which is what
 * selects the SSWU branch in `ECP.map2point` — so only the tag is wrong. Hence [hashToPoint]
 * below, which is MIRACL's routine with the specified tag; `BLS.java` is left out of the
 * vendored sources so nobody reaches for it by mistake.
 */
public object MiraclBls : BlsSignatureVerifier {

    private const val DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
    private const val G1_BYTES = 48
    private const val G2_BYTES = 96

    private const val COMPRESSED_FLAG = 0x80
    private const val INFINITY_FLAG = 0x40
    private const val SIGN_FLAG = 0x20

    override fun verify(publicKeyRaw: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val key = decodeG2(publicKeyRaw) ?: return false
        val point = decodeG1(signature) ?: return false

        // KeyValidate, from the BLS signature draft: the identity is a public key whose
        // matching secret key is known to everybody.
        if (key.is_infinity()) return false
        // Both points must be in the prime-order subgroup. Without this a point of small
        // order forges signatures on the cofactor part.
        if (!PAIR.G2member(key)) return false
        if (!PAIR.G1member(point)) return false

        val hashed = hashToPoint(message)
        val negated = ECP(point)
        negated.neg()

        // e(-signature, g2) * e(H(message), publicKey) == 1  <=>  e(signature, g2) == e(H(m), pk)
        val product = PAIR.fexp(PAIR.ate2(ECP2.generator(), negated, key, hashed))
        return product.isunity()
    }

    /**
     * `hash_to_curve` for G1, as RFC 9380 defines it: two field elements, each mapped to the
     * curve, added, then multiplied into the prime-order subgroup.
     *
     * This is MIRACL's `BLS.bls_hash_to_point` with the IC's domain separation tag. The field
     * step is `hash_to_field`, which MIRACL keeps package-private, so it is spelled out here.
     */
    internal fun hashToPoint(message: ByteArray, dst: String = DST): ECP {
        val u = hashToField(message, 2, dst)
        val point = ECP.map2point(u[0])
        point.add(ECP.map2point(u[1]))
        point.cfp()
        point.affine()
        return point
    }

    private fun hashToField(message: ByteArray, count: Int, dst: String): Array<FP> {
        val order = BIG(ROM.Modulus)
        val bits = order.nbits()
        // RFC 9380 L: enough bytes that reducing modulo p is statistically uniform.
        // Spelled as MIRACL spells it, so the two cannot drift apart.
        val width = (bits + CONFIG_CURVE.AESKEY * 8 - 1) / 8 + 1
        val expanded = HMAC.XMD_Expand(
            HMAC.MC_SHA2,
            CONFIG_CURVE.HASH_TYPE,
            width * count,
            dst.toByteArray(Charsets.UTF_8),
            message,
        )
        return Array(count) { i ->
            val slice = expanded.copyOfRange(i * width, (i + 1) * width)
            FP(DBIG.fromBytes(slice).ctmod(order, 8 * width - bits))
        }
    }

    /**
     * Reads the 48-byte compressed encoding of a G1 point.
     *
     * The top three bits of the first byte are flags: compressed, infinity, and the sign of y.
     * Note that this "sign" is *not* MIRACL's `FP.sign()`, which is the parity used by the
     * hash-to-curve draft. Point serialisation uses a different rule — y counts as signed when
     * it is the larger of `y` and `p - y` — so the choice is made here rather than by handing
     * the flag to MIRACL's `ECP(BIG, int)` constructor, which would silently pick the wrong
     * root for about half of all points.
     */
    internal fun decodeG1(bytes: ByteArray): ECP? {
        if (bytes.size != G1_BYTES) return null
        val flags = bytes[0].toInt() and 0xff
        if (flags and COMPRESSED_FLAG == 0) return null

        if (flags and INFINITY_FLAG != 0) {
            // The specification fixes every other bit at zero, so there is exactly one
            // encoding of infinity and no room to smuggle anything alongside it.
            if (flags != COMPRESSED_FLAG or INFINITY_FLAG) return null
            for (i in 1 until bytes.size) if (bytes[i].toInt() != 0) return null
            return ECP()
        }

        val stripped = bytes.copyOf()
        stripped[0] = (flags and 0x1f).toByte()
        val x = BIG.fromBytes(stripped)
        if (BIG.comp(x, field()) >= 0) return null

        val point = ECP(x)
        // MIRACL reports "x is not on the curve" by returning the point at infinity.
        if (point.is_infinity()) return null
        if (isLarger(point.getY()) != (flags and SIGN_FLAG != 0)) point.neg()
        return point
    }

    /**
     * Reads the 96-byte compressed encoding of a G2 point.
     *
     * The imaginary part of x comes first, which is the reverse of how [FP2] is written.
     */
    internal fun decodeG2(bytes: ByteArray): ECP2? {
        if (bytes.size != G2_BYTES) return null
        val flags = bytes[0].toInt() and 0xff
        if (flags and COMPRESSED_FLAG == 0) return null

        if (flags and INFINITY_FLAG != 0) {
            if (flags != COMPRESSED_FLAG or INFINITY_FLAG) return null
            for (i in 1 until bytes.size) if (bytes[i].toInt() != 0) return null
            return ECP2()
        }

        val imaginary = bytes.copyOfRange(0, G1_BYTES)
        imaginary[0] = (flags and 0x1f).toByte()
        val real = bytes.copyOfRange(G1_BYTES, G2_BYTES)
        val xi = BIG.fromBytes(imaginary)
        val xr = BIG.fromBytes(real)
        if (BIG.comp(xi, field()) >= 0 || BIG.comp(xr, field()) >= 0) return null

        val point = ECP2(FP2(xr, xi), 0)
        if (point.is_infinity()) return null
        val y = point.getY()
        if (isLarger(y.getB(), y.getA()) != (flags and SIGN_FLAG != 0)) point.neg()
        return point
    }

    /**
     * Whether `value` is the larger of itself and `p - value`, which is what the sign bit of a
     * compressed point records. Zero is its own negation, so it is never the larger one.
     */
    private fun isLarger(value: BIG): Boolean =
        !value.iszilch() && BIG.comp(value, BIG.modneg(value, field())) > 0

    /**
     * The same question for an element of Fp2, whose parts are ordered with the imaginary one
     * first: the imaginary part decides, and the real part only breaks a tie at zero.
     */
    private fun isLarger(imaginary: BIG, real: BIG): Boolean =
        if (imaginary.iszilch()) isLarger(real) else isLarger(imaginary)

    /** A fresh copy each time: MIRACL's arithmetic mutates its receivers. */
    private fun field(): BIG = BIG(ROM.Modulus)

    init {
        // The encodings below are one field element wide, and MIRACL reads exactly that many
        // bytes. If the vendored configuration ever changed curve, this is the first thing
        // that would stop being true.
        require(CONFIG_BIG.MODBYTES == G1_BYTES) {
            "the vendored curve has ${CONFIG_BIG.MODBYTES}-byte field elements, not $G1_BYTES"
        }
    }
}
