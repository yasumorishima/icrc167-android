package io.github.yasumorishima.icrc167.canistersig

/** Reads the hex fixtures under `src/test/resources/vectors`; see the README beside them. */
internal object Vectors {

    fun hex(name: String): ByteArray {
        val stream = checkNotNull(Vectors::class.java.getResourceAsStream("/vectors/$name.hex")) {
            "missing test vector $name"
        }
        val text = stream.use { it.readBytes() }.toString(Charsets.UTF_8).filter { !it.isWhitespace() }
        check(text.isNotEmpty()) { "test vector $name is empty" }
        return parse(text)
    }

    fun parse(text: String): ByteArray {
        require(text.length % 2 == 0) { "not a whole number of bytes: $text" }
        return ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
