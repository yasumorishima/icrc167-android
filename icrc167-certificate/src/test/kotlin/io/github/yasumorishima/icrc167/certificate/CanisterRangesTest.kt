package io.github.yasumorishima.icrc167.certificate

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CanisterRangesTest {

    /**
     * The blob from the sharded delegation in DFINITY's own test vector: one range, from
     * `ffffffffff9000000101` to `ffffffffff9fffff0101`.
     */
    private val realShard = hex("d9d9f781824affffffffff90000001014affffffffff9fffff0101")

    @Test
    fun `decodes a shard the IC actually produced`() {
        val ranges = CanisterRanges.decode(realShard)
        assertEquals(1, ranges.size)
        assertContentEquals(hex("ffffffffff9000000101"), ranges[0].first)
        assertContentEquals(hex("ffffffffff9fffff0101"), ranges[0].second)
    }

    @Test
    fun `both ends of a range are inside it`() {
        val ranges = CanisterRanges.decode(realShard)
        assertTrue(CanisterRanges.contains(ranges, hex("ffffffffff9000000101")))
        assertTrue(CanisterRanges.contains(ranges, hex("ffffffffff9fffff0101")))
        // The canister the sharded vector is about sits between the two ends.
        assertTrue(CanisterRanges.contains(ranges, hex("ffffffffff9000070101")))
    }

    /**
     * Principals order as unsigned bytes. Reading them as signed would put every canister with
     * a high first byte — which is every canister on this subnet — outside its own range.
     */
    @Test
    fun `a canister below or above the range is outside it`() {
        val ranges = CanisterRanges.decode(realShard)
        assertFalse(CanisterRanges.contains(ranges, hex("ffffffffff8fffff0101")))
        assertFalse(CanisterRanges.contains(ranges, hex("ffffffffffa000000101")))
        assertFalse(CanisterRanges.contains(ranges, hex("00000000006000270101")))
    }

    @Test
    fun `refuses ranges that are not a tagged array of pairs`() {
        assertFailsWith<CborException> { CanisterRanges.decode(hex("818241014102")) }
        assertFailsWith<CborException> { CanisterRanges.decode(hex("d9d9f78183410141024103")) }
    }

    // The shard search: the label to read is the greatest one not exceeding the target.
    // These cases follow the unit tests of DFINITY's own implementation.

    @Test
    fun `an empty or pruned subtree names no shard`() {
        assertNull(CanisterRanges.shardFor(HashTree.Empty, hex("10")))
        assertNull(CanisterRanges.shardFor(HashTree.Pruned(ByteArray(32)), hex("10")))
    }

    @Test
    fun `a single shard covers everything at or above its label`() {
        val tree = labeled("10", "A")
        assertContentEquals("A".toByteArray(), CanisterRanges.shardFor(tree, hex("20")))
        assertContentEquals("A".toByteArray(), CanisterRanges.shardFor(tree, hex("10")))
        assertNull(CanisterRanges.shardFor(tree, hex("05")))
    }

    @Test
    fun `picks the greatest label not exceeding the target`() {
        val tree = HashTree.Fork(labeled("10", "A"), labeled("30", "B"))
        assertContentEquals("A".toByteArray(), CanisterRanges.shardFor(tree, hex("20")))
        assertContentEquals("B".toByteArray(), CanisterRanges.shardFor(tree, hex("40")))
        assertNull(CanisterRanges.shardFor(tree, hex("05")))
    }

    /** A pruned right-hand branch must not hide the shard that is still readable on the left. */
    @Test
    fun `falls back to the left when the right branch is pruned`() {
        val tree = HashTree.Fork(labeled("10", "A"), HashTree.Pruned(ByteArray(32)))
        assertContentEquals("A".toByteArray(), CanisterRanges.shardFor(tree, hex("20")))
    }

    @Test
    fun `hands back the subtree below a path`() {
        val tree = HashTree.Fork(
            HashTree.Labeled("canister_ranges".toByteArray(), labeled("10", "A")),
            HashTree.Labeled("time".toByteArray(), HashTree.Leaf(byteArrayOf(1))),
        )
        val found = tree.lookupSubtree(listOf("canister_ranges".toByteArray()))
        assertIs<SubtreeLookup.Found>(found)
        assertContentEquals("A".toByteArray(), CanisterRanges.shardFor(found.subtree, hex("10")))

        assertIs<SubtreeLookup.Absent>(tree.lookupSubtree(listOf("subnet".toByteArray())))
    }

    /** Pruned is not Absent: nothing hangs below a path the witness dropped. */
    @Test
    fun `a pruned branch answers unknown, not absent`() {
        val tree = HashTree.Fork(
            HashTree.Labeled("a".toByteArray(), HashTree.Leaf(byteArrayOf(1))),
            HashTree.Pruned(ByteArray(32)),
        )
        assertIs<SubtreeLookup.Unknown>(tree.lookupSubtree(listOf("z".toByteArray())))
    }

    private fun labeled(label: String, value: String) =
        HashTree.Labeled(hex(label), HashTree.Leaf(value.toByteArray()))

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
