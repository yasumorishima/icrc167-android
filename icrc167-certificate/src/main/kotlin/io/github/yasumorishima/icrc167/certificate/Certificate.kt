package io.github.yasumorishima.icrc167.certificate

/**
 * A certificate: a witness of part of the IC state tree, plus the subnet's signature over
 * that tree's root hash.
 *
 * Holding one proves nothing on its own. [CanisterSignatureValidator] is what checks the
 * signature and reads a value out of the tree; this type only says what was on the wire.
 *
 * See the IC interface specification, "Certification".
 */
public class Certificate internal constructor(
    public val tree: HashTree,
    signature: ByteArray,
    public val delegation: CertificateDelegation?,
) {
    private val rawSignature: ByteArray = signature.copyOf()

    /** The BLS signature over `domain_sep("ic-state-root") · reconstruct(tree)`. */
    public val signature: ByteArray get() = rawSignature.copyOf()

    public companion object {
        public fun fromCbor(bytes: ByteArray): Certificate {
            val fields = cborSelfDescribedMap(bytes, "certificate")
            val delegation = fields["delegation"]?.let { CertificateDelegation.fromCbor(it) }
            return Certificate(
                tree = HashTree.fromCbor(fields.required("tree", "certificate")),
                signature = fields.requiredBytes("signature", "certificate"),
                delegation = delegation,
            )
        }
    }
}

/**
 * A subnet delegation: the root subnet's statement that some other subnet's key may certify
 * for a range of canisters.
 *
 * The inner certificate is kept as bytes rather than parsed here, because verifying the outer
 * certificate is what decides whether the inner one is worth looking at.
 */
public class CertificateDelegation internal constructor(
    subnetId: ByteArray,
    certificate: ByteArray,
) {
    private val rawSubnetId: ByteArray = subnetId.copyOf()
    private val rawCertificate: ByteArray = certificate.copyOf()

    public val subnetId: ByteArray get() = rawSubnetId.copyOf()

    /** The CBOR encoding of the root subnet's certificate. */
    public val certificate: ByteArray get() = rawCertificate.copyOf()

    internal companion object {
        fun fromCbor(value: CborValue): CertificateDelegation {
            val fields = cborTextKeyedMap(value, "delegation")
            return CertificateDelegation(
                subnetId = fields.requiredBytes("subnet_id", "delegation"),
                certificate = fields.requiredBytes("certificate", "delegation"),
            )
        }
    }
}

/**
 * An IC canister signature: a certificate, plus the witness whose root hash the signing
 * canister published as its certified data.
 *
 * See the IC interface specification, "Canister signatures".
 */
public class CanisterSignature internal constructor(
    certificate: ByteArray,
    public val tree: HashTree,
) {
    private val rawCertificate: ByteArray = certificate.copyOf()

    public val certificate: ByteArray get() = rawCertificate.copyOf()

    public companion object {
        public fun fromCbor(bytes: ByteArray): CanisterSignature {
            val fields = cborSelfDescribedMap(bytes, "canister signature")
            return CanisterSignature(
                certificate = fields.requiredBytes("certificate", "canister signature"),
                tree = HashTree.fromCbor(fields.required("tree", "canister signature")),
            )
        }
    }
}

/**
 * Reads the `#6.55799(map)` shape both a certificate and a canister signature are wrapped in,
 * and indexes the map by its text keys.
 *
 * Unknown keys are ignored — the specification may add some — but a repeated key is refused:
 * two entries for the same name mean two readers can disagree about what was signed.
 */
internal fun cborSelfDescribedMap(bytes: ByteArray, what: String): Map<String, CborValue> {
    val decoded = Cbor.decode(bytes)
    val tagged = decoded as? CborValue.Tagged
        ?: throw CborException("a $what is wrapped in the self-describe tag")
    if (tagged.tag != Cbor.SELF_DESCRIBE_TAG) {
        throw CborException("a $what carries tag ${Cbor.SELF_DESCRIBE_TAG}, not ${tagged.tag}")
    }
    return cborTextKeyedMap(tagged.value, what)
}

internal fun cborTextKeyedMap(value: CborValue, what: String): Map<String, CborValue> {
    val entries = (value as? CborValue.Entries)?.entries
        ?: throw CborException("a $what is a map")
    val fields = LinkedHashMap<String, CborValue>()
    for ((key, item) in entries) {
        val name = (key as? CborValue.Text)?.value ?: continue
        if (fields.put(name, item) != null) throw CborException("a $what has two '$name' entries")
    }
    return fields
}

internal fun Map<String, CborValue>.required(name: String, what: String): CborValue =
    this[name] ?: throw CborException("a $what has no '$name'")

internal fun Map<String, CborValue>.requiredBytes(name: String, what: String): ByteArray =
    (required(name, what) as? CborValue.Bytes)?.value
        ?: throw CborException("'$name' of a $what is a byte string")
