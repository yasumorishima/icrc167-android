package io.github.yasumorishima.icrc167.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * The Ed25519 key pair a delegation chain is issued to.
 *
 * Ed25519 rather than a hardware-backed key, because the Android Keystore cannot generate or
 * hold one below API 33 and the IC expects this curve. The seed is therefore kept in app
 * storage, encrypted under a Keystore-resident AES key so that it is not readable from a
 * backup or from another app's view of the filesystem.
 */
public class SessionKey private constructor(private val seed: ByteArray) {

    private val privateKey = Ed25519PrivateKeyParameters(seed, 0)

    /** DER SubjectPublicKeyInfo — the form ICRC-34 carries and the IC hashes into a principal. */
    public val publicKeyDer: ByteArray
        get() = SPKI_PREFIX + privateKey.generatePublicKey().encoded

    public fun sign(message: ByteArray): ByteArray = Ed25519Signer().apply {
        init(true, privateKey)
        update(message, 0, message.size)
    }.generateSignature()

    internal fun seedBytes(): ByteArray = seed.copyOf()

    public companion object {
        /** RFC 8410 SubjectPublicKeyInfo header for an Ed25519 key, followed by 32 raw bytes. */
        private val SPKI_PREFIX = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )

        public fun generate(): SessionKey {
            val seed = ByteArray(32)
            java.security.SecureRandom().nextBytes(seed)
            return SessionKey(seed)
        }

        internal fun fromSeed(seed: ByteArray): SessionKey {
            require(seed.size == 32) { "an Ed25519 seed is 32 bytes, got ${seed.size}" }
            return SessionKey(seed.copyOf())
        }
    }
}

/**
 * Persists one [SessionKey] across process death, encrypted under a Keystore AES key.
 *
 * A session key is not a long-term identity: it is the key a delegation is issued to, and the
 * delegation expires on its own. Losing it costs the user another sign-in, nothing more, so
 * [clear] is a reasonable answer to anything unexpected.
 */
public class SessionKeyStore(context: Context) {

    private val preferences =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    public fun loadOrCreate(): SessionKey = load() ?: SessionKey.generate().also { store(it) }

    public fun load(): SessionKey? {
        val packed = preferences.getString(SEED_KEY, null) ?: return null
        return try {
            val blob = Base64.getDecoder().decode(packed)
            val iv = blob.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = blob.copyOfRange(GCM_IV_BYTES, blob.size)
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            }
            SessionKey.fromSeed(cipher.doFinal(ciphertext))
        } catch (_: Exception) {
            // A rotated or invalidated Keystore key makes the stored seed permanently
            // unreadable. That is a lost session, not an error worth propagating.
            clear()
            null
        }
    }

    public fun clear() {
        preferences.edit().remove(SEED_KEY).apply()
    }

    private fun store(key: SessionKey) {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, wrappingKey())
        }
        val blob = cipher.iv + cipher.doFinal(key.seedBytes())
        preferences.edit()
            .putString(SEED_KEY, Base64.getEncoder().encodeToString(blob))
            .apply()
    }

    private fun wrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getEntry(WRAPPING_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)
            ?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                WRAPPING_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val PREFERENCES = "icrc167-session"
        const val SEED_KEY = "session-seed"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val WRAPPING_KEY_ALIAS = "icrc167-session-wrapping-key"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
    }
}
