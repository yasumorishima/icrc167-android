package io.github.yasumorishima.icrc167.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.AEADBadTagException
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
 * Holds session keys, encrypted under a Keystore AES key.
 *
 * There are two slots on purpose. Each attempt gets a **fresh** key, so that the same public
 * key is never presented to a signer twice — two sign-ins with different Internet Identity
 * anchors would otherwise be trivially linkable by the key alone. That new key only replaces
 * the [active] one when an attempt actually succeeds, so abandoning a sign-in does not
 * invalidate the delegation the app is already holding.
 */
public class SessionKeyStore(context: Context) {

    private val preferences =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    /** Mints a key for a new attempt, replacing any earlier unfinished one. */
    public fun beginAttempt(): SessionKey = synchronized(LOCK) {
        SessionKey.generate().also { store(PENDING_SEED, it) }
    }

    /** The key the pending attempt is bound to, if there is one. */
    public fun pending(): SessionKey? = synchronized(LOCK) { load(PENDING_SEED) }

    /** The key a completed sign-in is bound to. */
    public fun active(): SessionKey? = synchronized(LOCK) { load(ACTIVE_SEED) }

    /**
     * Makes [key] the active one and forgets the pending slot. It takes the key the chain was
     * verified against instead of reading the pending slot again: a second read can fail on a
     * transient Keystore error or find a different key, and either would leave the chain bound
     * to a key it does not name. Throws if the key cannot be stored.
     */
    public fun promote(key: SessionKey): Unit = synchronized(LOCK) {
        store(ACTIVE_SEED, key)
        preferences.edit().remove(PENDING_SEED).apply()
    }

    /** Promotes whatever the pending slot holds, or returns null. Prefer [promote]. */
    public fun promotePending(): SessionKey? {
        synchronized(LOCK) {
            val key = load(PENDING_SEED) ?: return null
            store(ACTIVE_SEED, key)
            preferences.edit().remove(PENDING_SEED).apply()
            return key
        }
    }

    public fun discardPending(): Unit = synchronized(LOCK) {
        preferences.edit().remove(PENDING_SEED).apply()
    }

    public fun clear(): Unit = synchronized(LOCK) {
        preferences.edit().remove(PENDING_SEED).remove(ACTIVE_SEED).apply()
    }

    private fun load(slot: String): SessionKey? {
        val packed = preferences.getString(slot, null) ?: return null
        return try {
            val blob = Base64.getDecoder().decode(packed)
            val iv = blob.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = blob.copyOfRange(GCM_IV_BYTES, blob.size)
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            }
            SessionKey.fromSeed(cipher.doFinal(ciphertext))
        } catch (e: Exception) {
            // Only discard the seed for failures that mean it can never be read again. A
            // transient Keystore error must not be answered by destroying the user's session.
            val permanent = e is AEADBadTagException ||
                e is KeyPermanentlyInvalidatedException ||
                e is IllegalArgumentException
            if (permanent) preferences.edit().remove(slot).apply()
            null
        }
    }

    private fun store(slot: String, key: SessionKey) {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, wrappingKey())
        }
        val blob = cipher.iv + cipher.doFinal(key.seedBytes())
        preferences.edit()
            .putString(slot, Base64.getEncoder().encodeToString(blob))
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
        /**
         * One lock for every store in the process, not one per instance: they all read and
         * write the same preferences file, and each client builds its own store.
         */
        val LOCK = Any()

        const val PREFERENCES = "icrc167-session"
        const val PENDING_SEED = "pending-seed"
        const val ACTIVE_SEED = "active-seed"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val WRAPPING_KEY_ALIAS = "icrc167-session-wrapping-key"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
    }
}
