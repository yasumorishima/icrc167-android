package io.github.yasumorishima.icrc167.agent

import io.github.yasumorishima.icrc167.ReprHash

/**
 * The one place a CBOR value is turned into something the request-id hash can take.
 *
 * Both directions of the protocol need it — the content map this library sends, and the
 * response map a node signed — and both have to agree with the specification's `hash_of_map`
 * exactly. One converter means there is one thing to be right about.
 */
internal fun CborItem.toReprValue(): ReprHash.Value = when (this) {
    is CborItem.Text -> ReprHash.Value.Text(value)
    is CborItem.Blob -> ReprHash.Value.Blob(bytes)
    is CborItem.Uint -> ReprHash.Value.Nat(value)
    is CborItem.Arr -> ReprHash.Value.Arr(items.map { it.toReprValue() })
    is CborItem.Dict -> ReprHash.Value.Map(
        LinkedHashMap<String, ReprHash.Value>(entries.size).also { fields ->
            for ((key, value) in entries) {
                val name = (key as? CborItem.Text)?.value
                    ?: throw IcAgentException("a map field is not named by text")
                // Refused rather than resolved, the same way AgentCbor.textMap does: a map
                // with the field twice hashes to whichever one the reader happened to keep.
                if (fields.put(name, value.toReprValue()) != null) {
                    throw IcAgentException("a map gives the field " + name + " twice")
                }
            }
        },
    )
    // A tag has no defined hash and nothing that gets hashed carries one.
    is CborItem.Tagged -> throw IcAgentException("no hash is defined for a tagged value")
}

/** The fields of a text-keyed map, in the form the hash takes. */
internal fun CborItem.Dict.toReprFields(): Map<String, ReprHash.Value> =
    (toReprValue() as ReprHash.Value.Map).fields
