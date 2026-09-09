package io.github.yasumorishima.icrc167.canistersig

import io.github.yasumorishima.icrc167.certificate.Cbor
import io.github.yasumorishima.icrc167.certificate.HashTree
import io.github.yasumorishima.icrc167.certificate.reconstruct

/**
 * Builds and rebuilds certificates, so a test can ask what happens to a *particular* edit.
 *
 * The interesting attacks on a witness are edits that leave the root hash alone, because the
 * signature is over the root hash and nothing else. Pruning is the whole family: replacing a
 * subtree with its own digest is exactly what the format is for. There is no way to try that
 * without being able to write a certificate back out, so this writes one.
 *
 * Encoding only — the reader under test is the one in the library, and every fixture built
 * here is checked to still verify before anything is changed in it.
 */
internal object CertificateFixtures {

    fun uint(value: Long): ByteArray = header(0, value)

    fun bytes(value: ByteArray): ByteArray = header(2, value.size.toLong()) + value

    fun text(value: String): ByteArray {
        val utf8 = value.toByteArray(Charsets.UTF_8)
        return header(3, utf8.size.toLong()) + utf8
    }

    fun array(vararg items: ByteArray): ByteArray =
        header(4, items.size.toLong()) + (items.reduceOrNull(ByteArray::plus) ?: ByteArray(0))

    fun map(vararg entries: Pair<String, ByteArray>): ByteArray =
        header(5, entries.size.toLong()) +
            (entries.map { text(it.first) + it.second }.reduceOrNull(ByteArray::plus) ?: ByteArray(0))

    fun selfDescribed(value: ByteArray): ByteArray = header(6, Cbor.SELF_DESCRIBE_TAG) + value

    /** The array encoding the IC uses for witnesses, as read by `HashTree.fromCbor`. */
    fun tree(node: HashTree): ByteArray = when (node) {
        is HashTree.Empty -> array(uint(0))
        is HashTree.Fork -> array(uint(1), tree(node.left), tree(node.right))
        is HashTree.Labeled -> array(uint(2), bytes(node.label), tree(node.subtree))
        is HashTree.Leaf -> array(uint(3), bytes(node.value))
        is HashTree.Pruned -> array(uint(4), bytes(node.hash))
    }

    fun certificate(tree: HashTree, signature: ByteArray, delegation: ByteArray? = null): ByteArray {
        val entries = mutableListOf(
            "tree" to tree(tree),
            "signature" to bytes(signature),
        )
        if (delegation != null) entries.add("delegation" to delegation)
        return selfDescribed(map(*entries.toTypedArray()))
    }

    fun delegation(subnetId: ByteArray, certificate: ByteArray): ByteArray =
        map("subnet_id" to bytes(subnetId), "certificate" to bytes(certificate))

    fun canisterSignature(certificate: ByteArray, tree: HashTree): ByteArray =
        selfDescribed(map("certificate" to bytes(certificate), "tree" to tree(tree)))

    /**
     * Replaces whatever hangs at [path] with the result of [edit], leaving the rest alone.
     *
     * Returns the tree unchanged when the path is not there, which a caller must not mistake
     * for having made the edit; the tests below check the root hash to be sure.
     */
    fun replaceAt(node: HashTree, path: List<ByteArray>, edit: (HashTree) -> HashTree): HashTree {
        if (path.isEmpty()) return edit(node)
        return when (node) {
            is HashTree.Fork -> HashTree.Fork(
                replaceAt(node.left, path, edit),
                replaceAt(node.right, path, edit),
            )
            is HashTree.Labeled ->
                if (node.label.contentEquals(path[0])) {
                    HashTree.Labeled(node.label, replaceAt(node.subtree, path.drop(1), edit))
                } else {
                    node
                }
            else -> node
        }
    }

    /** Prunes the subtree at [path]: the same root hash, one fewer thing the witness proves. */
    fun pruneAt(node: HashTree, path: List<ByteArray>): HashTree =
        replaceAt(node, path) { HashTree.Pruned(it.reconstruct()) }

    /**
     * A `SubjectPublicKeyInfo` for OID 1.3.6.1.4.1.56387.1.2 around
     * `|canister_id| . canister_id . seed`. Short-form lengths, so keep the seed small.
     */
    fun canisterSigKeyDer(canisterId: ByteArray, seed: ByteArray): ByteArray {
        val payload = byteArrayOf(canisterId.size.toByte()) + canisterId + seed
        val algorithm = byteArrayOf(
            0x30, 0x0c, 0x06, 0x0a,
            0x2B, 0x06, 0x01, 0x04, 0x01, 0x83.toByte(), 0xB8.toByte(), 0x43, 0x01, 0x02,
        )
        val bitString = byteArrayOf(0x03, (payload.size + 1).toByte(), 0x00) + payload
        val body = algorithm + bitString
        check(body.size < 0x80) { "the short-form length here only covers small keys" }
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /** `tagged<[*[start, end]]>`, the blob both canister-range shapes hold. */
    fun ranges(vararg spans: Pair<ByteArray, ByteArray>): ByteArray =
        selfDescribed(array(*spans.map { array(bytes(it.first), bytes(it.second)) }.toTypedArray()))

    fun label(value: String): ByteArray = value.toByteArray(Charsets.UTF_8)

    /** A forest of labelled subtrees, in the increasing order a well-formed tree requires. */
    fun forest(vararg children: Pair<String, HashTree>): HashTree =
        children
            .sortedWith { a, b -> compareLabels(a.first, b.first) }
            .map { HashTree.Labeled(label(it.first), it.second) as HashTree }
            .reduce { left, right -> HashTree.Fork(left, right) }

    fun labelled(vararg children: Pair<ByteArray, HashTree>): HashTree =
        children
            .sortedWith { a, b -> compareBytes(a.first, b.first) }
            .map { HashTree.Labeled(it.first, it.second) as HashTree }
            .reduce { left, right -> HashTree.Fork(left, right) }

    private fun compareLabels(a: String, b: String): Int =
        compareBytes(label(a), label(b))

    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }

    private fun header(major: Int, argument: Long): ByteArray {
        // Silently truncating a large argument into a four-byte header would encode a
        // different value than asked for, and every fixture built on it would be testing
        // something nobody wrote.
        require(argument in 0..0xFFFFFFFFL) { "argument $argument does not fit a CBOR header here" }
        val prefix = major shl 5
        return when {
            argument < 24 -> byteArrayOf((prefix or argument.toInt()).toByte())
            argument < 0x100 -> byteArrayOf((prefix or 24).toByte(), argument.toByte())
            argument < 0x10000 -> byteArrayOf(
                (prefix or 25).toByte(),
                (argument shr 8).toByte(),
                argument.toByte(),
            )
            else -> byteArrayOf(
                (prefix or 26).toByte(),
                (argument shr 24).toByte(),
                (argument shr 16).toByte(),
                (argument shr 8).toByte(),
                argument.toByte(),
            )
        }
    }
}
