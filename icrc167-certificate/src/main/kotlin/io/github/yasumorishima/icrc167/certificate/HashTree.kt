package io.github.yasumorishima.icrc167.certificate

import java.security.MessageDigest

/**
 * An IC state-tree witness.
 *
 * A certificate proves one thing: that [reconstruct] of this tree equals the root hash the
 * subnet signed. Everything a caller wants to know is then read out of the tree with
 * [lookupPath], which is careful to distinguish "this path is not in the state" from "this
 * part of the tree was pruned away, so I cannot tell" — conflating those two is how a
 * verifier gets talked into accepting an absence it never proved.
 */
public sealed interface HashTree {
    public object Empty : HashTree

    public class Fork(public val left: HashTree, public val right: HashTree) : HashTree

    // The byte arrays below are held privately and handed out as copies. A witness is
    // checked once and read many times; a caller that mutated one afterwards would be
    // reading something the root hash never covered.
    public class Labeled(label: ByteArray, public val subtree: HashTree) : HashTree {
        internal val rawLabel: ByteArray = label.copyOf()
        public val label: ByteArray get() = rawLabel.copyOf()
    }

    public class Leaf(value: ByteArray) : HashTree {
        internal val rawValue: ByteArray = value.copyOf()
        public val value: ByteArray get() = rawValue.copyOf()
    }

    public class Pruned(hash: ByteArray) : HashTree {
        internal val rawHash: ByteArray = hash.copyOf()
        public val hash: ByteArray get() = rawHash.copyOf()
    }

    public companion object {
        private const val NODE_EMPTY = 0L
        private const val NODE_FORK = 1L
        private const val NODE_LABELED = 2L
        private const val NODE_LEAF = 3L
        private const val NODE_PRUNED = 4L
        private const val DIGEST_BYTES = 32

        /** Reads the array encoding the IC uses for witnesses. */
        public fun fromCbor(value: CborValue): HashTree {
            val items = (value as? CborValue.Items)?.items
                ?: throw CborException("a hash tree node is an array")
            val tag = (items.firstOrNull() as? CborValue.Unsigned)?.value
                ?: throw CborException("a hash tree node starts with its type")

            fun bytesAt(index: Int): ByteArray =
                (items.getOrNull(index) as? CborValue.Bytes)?.value
                    ?: throw CborException("expected a byte string at position $index")

            fun treeAt(index: Int): HashTree =
                fromCbor(items.getOrNull(index) ?: throw CborException("missing subtree at $index"))

            return when (tag) {
                NODE_EMPTY -> {
                    if (items.size != 1) throw CborException("Empty takes no arguments")
                    Empty
                }
                NODE_FORK -> {
                    if (items.size != 3) throw CborException("Fork takes two subtrees")
                    Fork(treeAt(1), treeAt(2))
                }
                NODE_LABELED -> {
                    if (items.size != 3) throw CborException("Labeled takes a label and a subtree")
                    Labeled(bytesAt(1), treeAt(2))
                }
                NODE_LEAF -> {
                    if (items.size != 2) throw CborException("Leaf takes one value")
                    Leaf(bytesAt(1))
                }
                NODE_PRUNED -> {
                    if (items.size != 2) throw CborException("Pruned takes one digest")
                    val hash = bytesAt(1)
                    // A short "digest" here would let a forged subtree hash to something
                    // the caller never checked the length of.
                    if (hash.size != DIGEST_BYTES) {
                        throw CborException("a pruned digest is $DIGEST_BYTES bytes, got ${hash.size}")
                    }
                    Pruned(hash)
                }
                else -> throw CborException("unknown hash tree node type $tag")
            }
        }
    }
}

/** What a path lookup found. The three failure kinds are not interchangeable. */
public sealed interface Lookup {
    public class Found(public val value: ByteArray) : Lookup

    /** The tree proves the path is not in the state. */
    public object Absent : Lookup

    /** The witness was pruned here; nothing is proved either way. */
    public object Unknown : Lookup

    /** The path runs into a node that cannot contain it. */
    public object Error : Lookup
}

/**
 * `H(domain_sep(kind) · …)` for each node kind, exactly as the interface specification
 * defines it, where `domain_sep(s) = byte(|s|) · s`.
 */
public fun HashTree.reconstruct(): ByteArray = when (this) {
    is HashTree.Empty -> sha256(domainSeparator("ic-hashtree-empty"))
    is HashTree.Fork ->
        sha256(domainSeparator("ic-hashtree-fork"), left.reconstruct(), right.reconstruct())
    is HashTree.Labeled ->
        sha256(domainSeparator("ic-hashtree-labeled"), rawLabel, subtree.reconstruct())
    is HashTree.Leaf -> sha256(domainSeparator("ic-hashtree-leaf"), rawValue)
    // A pruned node *is* its digest; that is the whole point of pruning.
    is HashTree.Pruned -> rawHash.copyOf()
}

/** Follows a path of labels, per `lookup_path` in the interface specification. */
public fun HashTree.lookupPath(path: List<ByteArray>): Lookup {
    var node: HashTree = this
    for (label in path) {
        when (val found = findLabel(label, flattenForks(node))) {
            is LabelSearch.Found -> node = found.subtree
            LabelSearch.Absent -> return Lookup.Absent
            LabelSearch.Unknown -> return Lookup.Unknown
        }
    }
    return when (node) {
        is HashTree.Leaf -> Lookup.Found(node.rawValue.copyOf())
        is HashTree.Empty -> Lookup.Absent
        is HashTree.Pruned -> Lookup.Unknown
        is HashTree.Labeled, is HashTree.Fork -> Lookup.Error
    }
}

public fun HashTree.lookupPath(vararg path: String): Lookup =
    lookupPath(path.map { it.toByteArray(Charsets.UTF_8) })

/**
 * What a subtree lookup found. The failure kinds mean what they mean in [Lookup]: only
 * [Absent] is a proof, and it is a proof about the state, not about this witness.
 */
public sealed interface SubtreeLookup {
    public class Found(public val subtree: HashTree) : SubtreeLookup

    /** The tree proves nothing hangs below the path. */
    public object Absent : SubtreeLookup

    /** The witness was pruned on the way; nothing is proved either way. */
    public object Unknown : SubtreeLookup
}

/**
 * Follows a path of labels and hands back whatever hangs below it, rather than insisting the
 * path ends at a leaf.
 *
 * Needed where the interesting structure is the shape below a path and not one value: the
 * shards under `/canister_ranges/<subnet_id>` are labelled with the canister id each one
 * starts at, so the caller has to search them rather than name one.
 */
public fun HashTree.lookupSubtree(path: List<ByteArray>): SubtreeLookup {
    var node: HashTree = this
    for (label in path) {
        when (val found = findLabel(label, flattenForks(node))) {
            is LabelSearch.Found -> node = found.subtree
            LabelSearch.Absent -> return SubtreeLookup.Absent
            LabelSearch.Unknown -> return SubtreeLookup.Unknown
        }
    }
    return SubtreeLookup.Found(node)
}

/**
 * Labelled subtrees appear in strictly increasing label order and are never mixed with
 * leaves. [lookupPath] relies on that ordering to conclude absence, so a tree that breaks it
 * must be rejected before its answers are believed.
 */
public fun HashTree.isWellFormed(): Boolean {
    // `well_formed(tree) = (tree = Leaf _) v well_formed_forest(flatten_forks(tree))`:
    // a leaf is well formed as a whole tree, and only as a whole tree.
    if (this is HashTree.Leaf) return true

    val forest = flattenForks(this)
    val labels = ArrayList<ByteArray>()
    for (node in forest) {
        when (node) {
            is HashTree.Labeled -> {
                labels.add(node.rawLabel)
                if (!node.subtree.isWellFormed()) return false
            }
            is HashTree.Pruned -> Unit
            // `∀ t ∈ trees. t ≠ Leaf _`. Having already returned for a bare leaf above,
            // one appearing inside a forest is a tree the IC would never have produced.
            is HashTree.Leaf -> return false
            // flatten_forks emits neither of these; matched so the compiler keeps this
            // exhaustive if the node types ever grow.
            is HashTree.Empty, is HashTree.Fork -> return false
        }
    }
    for (i in 0 until labels.size - 1) {
        if (compareUnsigned(labels[i], labels[i + 1]) >= 0) return false
    }
    return true
}

private sealed interface LabelSearch {
    class Found(val subtree: HashTree) : LabelSearch
    object Absent : LabelSearch
    object Unknown : LabelSearch
}

private fun flattenForks(tree: HashTree): List<HashTree> = when (tree) {
    is HashTree.Empty -> emptyList()
    is HashTree.Fork -> flattenForks(tree.left) + flattenForks(tree.right)
    else -> listOf(tree)
}

/**
 * Absence is only provable when the label would have had to sit between two labels that are
 * actually present, or outside the range the forest covers. A pruned node anywhere it could
 * have been leaves the answer [LabelSearch.Unknown] — which is why adjacency is judged in the
 * forest as it stands, not in the labelled nodes filtered out of it.
 */
private fun findLabel(label: ByteArray, forest: List<HashTree>): LabelSearch {
    forest.forEach {
        if (it is HashTree.Labeled && it.rawLabel.contentEquals(label)) return LabelSearch.Found(it.subtree)
    }
    for (i in 0 until forest.size - 1) {
        val left = forest[i]
        val right = forest[i + 1]
        if (left is HashTree.Labeled && right is HashTree.Labeled &&
            compareUnsigned(left.rawLabel, label) < 0 && compareUnsigned(label, right.rawLabel) < 0
        ) {
            return LabelSearch.Absent
        }
    }
    (forest.firstOrNull() as? HashTree.Labeled)
        ?.let { if (compareUnsigned(label, it.rawLabel) < 0) return LabelSearch.Absent }
    (forest.lastOrNull() as? HashTree.Labeled)
        ?.let { if (compareUnsigned(it.rawLabel, label) < 0) return LabelSearch.Absent }
    if (forest.isEmpty()) return LabelSearch.Absent
    if (forest.size == 1 && forest[0] is HashTree.Leaf) return LabelSearch.Absent
    return LabelSearch.Unknown
}

/** Kotlin's Byte is signed, and label order is not. */
internal fun compareUnsigned(a: ByteArray, b: ByteArray): Int {
    val shared = minOf(a.size, b.size)
    for (i in 0 until shared) {
        val diff = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
        if (diff != 0) return diff
    }
    return a.size - b.size
}

internal fun domainSeparator(name: String): ByteArray =
    byteArrayOf(name.length.toByte()) + name.toByteArray(Charsets.UTF_8)

private fun sha256(vararg parts: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    for (part in parts) digest.update(part)
    return digest.digest()
}
