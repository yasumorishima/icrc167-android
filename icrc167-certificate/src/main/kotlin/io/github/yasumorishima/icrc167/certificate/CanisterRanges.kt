package io.github.yasumorishima.icrc167.certificate

/**
 * The set of canisters a delegated subnet is allowed to certify for.
 *
 * The state tree carries this in two shapes and both are live: the whole set in one blob at
 * `/subnet/<subnet_id>/canister_ranges`, and the same set split into shards at
 * `/canister_ranges/<subnet_id>/<start>` so a client can binary-search it. A verifier that
 * knows only one of them either rejects current certificates or rejects older ones, so both
 * are read here — the sharded form first, as the reference implementation does.
 */
internal object CanisterRanges {

    /** Decodes `tagged<[*[start, end]]>`, the encoding both shapes use for the blob itself. */
    fun decode(blob: ByteArray): List<Pair<ByteArray, ByteArray>> {
        val decoded = Cbor.decode(blob)
        val tagged = decoded as? CborValue.Tagged
            ?: throw CborException("canister ranges are wrapped in the self-describe tag")
        if (tagged.tag != Cbor.SELF_DESCRIBE_TAG) {
            throw CborException("canister ranges carry tag ${tagged.tag}")
        }
        val items = (tagged.value as? CborValue.Items)?.items
            ?: throw CborException("canister ranges are an array")
        return items.map { item ->
            val pair = (item as? CborValue.Items)?.items
                ?: throw CborException("a canister range is an array")
            if (pair.size != 2) throw CborException("a canister range has two ends, got ${pair.size}")
            val start = (pair[0] as? CborValue.Bytes)?.value
                ?: throw CborException("a canister range end is a byte string")
            val end = (pair[1] as? CborValue.Bytes)?.value
                ?: throw CborException("a canister range end is a byte string")
            start to end
        }
    }

    /** Principals are ordered as unsigned byte strings, and ranges are inclusive at both ends. */
    fun contains(ranges: List<Pair<ByteArray, ByteArray>>, canisterId: ByteArray): Boolean =
        ranges.any { (start, end) ->
            compareUnsigned(start, canisterId) <= 0 && compareUnsigned(canisterId, end) <= 0
        }

    /**
     * Finds the shard that would hold [canisterId] under `/canister_ranges/<subnet_id>`.
     *
     * Shards are labelled with the first canister id they cover and appear in increasing
     * order, so the one to read is the greatest label not exceeding the target. Walking the
     * witness right-first finds it in one pass; a pruned or empty branch simply has no answer,
     * which is why this returns null rather than treating "not found here" as "not covered".
     */
    fun shardFor(node: HashTree, canisterId: ByteArray): ByteArray? = when (node) {
        is HashTree.Empty, is HashTree.Pruned -> null
        is HashTree.Leaf -> node.value
        is HashTree.Labeled ->
            if (compareUnsigned(node.label, canisterId) <= 0) shardFor(node.subtree, canisterId) else null
        // Every label on the right is greater than every label on the left, so a hit on the
        // right is always the better lower bound.
        is HashTree.Fork ->
            shardFor(node.right, canisterId) ?: shardFor(node.left, canisterId)
    }
}
