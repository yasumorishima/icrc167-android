package io.github.yasumorishima.icrc167.certificate

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The two witnesses below are published fixtures, not something this repository produced.
 * They describe the same state — the second is the first with parts pruned away — so the
 * root hash they reconstruct to has to be identical. A hash function that agreed with
 * itself but not with the IC would pass a round trip and fail against a replica.
 */
class HashTreeTest {

    private val fullTree = (
        "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c64" +
            "83024162820344676f6f648301830241638100830241648203476d6f726e696e67"
        ).hexToBytes()

    private val prunedTree = (
        "83018301830241618301820458201b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f1" +
            "0f71ce3749f5a63883024179820345776f726c6483024162820458207b32ac0c6ba8ce35ac" +
            "82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6830182045820ec8324b8a1f1ac16" +
            "bd2e806edba78006479c9877fed4eb464a25485465af601d830241648203476d6f726e696e67"
        ).hexToBytes()

    private val expectedRoot = "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0"

    private fun parse(bytes: ByteArray) = HashTree.fromCbor(Cbor.decode(bytes))

    @Test
    fun `reconstructs the published root hash`() {
        assertEquals(expectedRoot, parse(fullTree).reconstruct().toHex())
    }

    @Test
    fun `pruning does not change the root hash`() {
        assertEquals(expectedRoot, parse(prunedTree).reconstruct().toHex())
    }

    @Test
    fun `both witnesses are well formed`() {
        assertTrue(parse(fullTree).isWellFormed())
        assertTrue(parse(prunedTree).isWellFormed())
    }

    // ---- reading values out ---------------------------------------------------------

    @Test
    fun `finds values at their paths`() {
        val tree = parse(fullTree)
        assertEquals("hello", (tree.lookupPath("a", "x") as Lookup.Found).value.decodeToString())
        assertEquals("world", (tree.lookupPath("a", "y") as Lookup.Found).value.decodeToString())
        assertEquals("good", (tree.lookupPath("b") as Lookup.Found).value.decodeToString())
        assertEquals("morning", (tree.lookupPath("d") as Lookup.Found).value.decodeToString())
    }

    @Test
    fun `reports absence when the tree proves it`() {
        val tree = parse(fullTree)
        // `c` is present but empty, and `e` would have to sit after the last label there is.
        assertIs<Lookup.Absent>(tree.lookupPath("c"))
        assertIs<Lookup.Absent>(tree.lookupPath("e"))
        assertIs<Lookup.Absent>(tree.lookupPath("a", "z"))
    }

    @Test
    fun `will not claim absence across a pruned sibling`() {
        // This is the one that matters. In the full witness `c` is provably empty; in the
        // pruned one the node that would have held it is a digest, so the honest answer is
        // that nothing was proved. A verifier that answered Absent here would accept an
        // absence the subnet never signed for.
        val tree = parse(prunedTree)
        assertIs<Lookup.Unknown>(tree.lookupPath("c"))
        assertIs<Lookup.Unknown>(tree.lookupPath("a", "x"))
        assertIs<Lookup.Unknown>(tree.lookupPath("b"))
        // Whatever survived pruning still reads back.
        assertEquals("world", (tree.lookupPath("a", "y") as Lookup.Found).value.decodeToString())
        assertEquals("morning", (tree.lookupPath("d") as Lookup.Found).value.decodeToString())
    }

    @Test
    fun `a path that runs into a labelled node is an error, not an absence`() {
        assertIs<Lookup.Error>(parse(fullTree).lookupPath("a"))
    }

    // ---- rejecting malformed input ---------------------------------------------------

    @Test
    fun `rejects labels that are not in increasing order`() {
        // lookupPath concludes absence from the ordering, so a tree without it must not be
        // believed in the first place.
        val outOfOrder = HashTree.Fork(
            HashTree.Labeled("b".toByteArray(), HashTree.Leaf(byteArrayOf(1))),
            HashTree.Labeled("a".toByteArray(), HashTree.Leaf(byteArrayOf(2))),
        )
        assertFalse(outOfOrder.isWellFormed())
    }

    @Test
    fun `rejects a leaf that is not the whole tree`() {
        // well_formed_forest requires no element of the forest to be a leaf; a leaf is only
        // well formed as a tree in its own right. Reading the rule as "at most one leaf and
        // no labels" instead lets this through.
        val leafInsideAFork = HashTree.Fork(HashTree.Leaf(byteArrayOf(1)), HashTree.Empty)
        assertFalse(leafInsideAFork.isWellFormed())

        val leafBesideALabel = HashTree.Fork(
            HashTree.Labeled("a".toByteArray(), HashTree.Leaf(byteArrayOf(1))),
            HashTree.Leaf(byteArrayOf(2)),
        )
        assertFalse(leafBesideALabel.isWellFormed())

        // A bare leaf, and an empty tree, remain well formed.
        assertTrue(HashTree.Leaf(byteArrayOf(1)).isWellFormed())
        assertTrue(HashTree.Empty.isWellFormed())
    }

    @Test
    fun `rejects a pruned digest of the wrong length`() {
        // 8204 43 aabbcc = Pruned(3 bytes)
        val error = assertFailsWith<CborException> { parse("820443aabbcc".hexToBytes()) }
        assertTrue(error.message!!.contains("pruned digest"))
    }

    @Test
    fun `rejects an unknown node type`() {
        val error = assertFailsWith<CborException> { parse("820541ff".hexToBytes()) }
        assertTrue(error.message!!.contains("unknown hash tree node type"))
    }

    @Test
    fun `absence depends on where the pruned node sits`() {
        val label = "b".toByteArray()

        // A digest before the first label could have been hiding it, so nothing is proved.
        val prunedFirst = HashTree.Fork(
            HashTree.Pruned(ByteArray(32)),
            HashTree.Labeled("c".toByteArray(), HashTree.Leaf(byteArrayOf(1))),
        )
        assertIs<Lookup.Unknown>(prunedFirst.lookupPath(listOf(label)))

        // A digest *after* a larger first label cannot be: labels only increase, so nothing
        // smaller than the first one can be further along.
        val prunedLast = HashTree.Fork(
            HashTree.Labeled("c".toByteArray(), HashTree.Leaf(byteArrayOf(1))),
            HashTree.Pruned(ByteArray(32)),
        )
        assertIs<Lookup.Absent>(prunedLast.lookupPath(listOf(label)))
    }

    @Test
    fun `a witness read out of the tree cannot be edited afterwards`() {
        val tree = parse(fullTree)
        val first = (tree.lookupPath("b") as Lookup.Found).value
        first[0] = 0
        assertEquals("good", (tree.lookupPath("b") as Lookup.Found).value.decodeToString())
    }

    @Test
    fun `label order is compared as unsigned`() {
        // 0x80 is negative as a Kotlin Byte; signed comparison would sort it before 0x01.
        assertTrue(compareUnsigned(byteArrayOf(0x01), byteArrayOf(0x80.toByte())) < 0)
    }

    @Test
    fun `the domain separator is the length byte followed by the name`() {
        val separator = domainSeparator("ic-hashtree-leaf")
        assertEquals(16, separator[0].toInt())
        assertEquals("ic-hashtree-leaf".length + 1, separator.size)
    }
}

internal fun String.hexToBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
