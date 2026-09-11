package io.github.yasumorishima.icrc167.android

import android.content.pm.ApplicationInfo
import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.yasumorishima.icrc167.canistersig.MiraclBls
import io.github.yasumorishima.icrc167.certificate.BlsSignatureVerifier
import io.github.yasumorishima.icrc167.certificate.CertificateVerification
import io.github.yasumorishima.icrc167.certificate.CertificateVerifier
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * How long verifying a real IC certificate takes on a device.
 *
 * The certificate is the one id.ai served on 2026-09-09, shared with icrc167-canister-sig's
 * tests rather than copied. It carries a subnet delegation, so verifying it means two BLS
 * verifications, the delegation under the root key and the certificate under the subnet key:
 * the part of checking a real Internet Identity chain that needs pairing arithmetic.
 *
 * The line goes to logcat, where scripts/device-tests.sh prints it into the CI log. An emulator
 * on a KVM host running a debuggable APK says little about a phone, so the bound on the cold
 * run is not a target: it is three times the slowest of three measured runs, there to catch a
 * regression. The test also asserts that the timed work really was a verification: both BLS
 * checks ran and both passed.
 */
@RunWith(AndroidJUnit4::class)
class VerificationTimingTest {

    @Test
    fun verifyingARealCertificateIsTimed() {
        val certificate = vector("live-certificate")
        val canisterId = vector("live-canister-id")
        val calls = AtomicInteger()
        val passed = AtomicInteger()
        val counting = BlsSignatureVerifier { key, message, signature ->
            calls.incrementAndGet()
            MiraclBls.verify(key, message, signature).also { if (it) passed.incrementAndGet() }
        }
        val verifier = CertificateVerifier(counting)

        // The first call in a process is the slow one, two to four times the warm median in the
        // runs so far, and a real sign-in happens about once per process, so this is the number
        // that matters most. It is only cold if nothing earlier in this test process touched
        // MIRACL, which the other tests do not.
        val cold = timed { verifier.verify(certificate, canisterId) }
        assertTrue(cold.second.toString(), cold.second is CertificateVerification.Valid)
        assertEquals("BLS verifications in one certificate check", 2, calls.get())
        assertEquals("BLS verifications that passed", 2, passed.get())

        val warm = (1..WARM_RUNS).map {
            val run = timed { verifier.verify(certificate, canisterId) }
            assertTrue(run.second.toString(), run.second is CertificateVerification.Valid)
            run.first
        }
        val sorted = warm.sorted()
        Log.i(
            TAG,
            "ICRC167_TIMING cold_ms=${cold.first} warm_ms=${warm.joinToString(",")}" +
                " median_ms=${sorted[sorted.size / 2]} min_ms=${sorted.first()} max_ms=${sorted.last()}" +
                " api=${Build.VERSION.SDK_INT} abi=${Build.SUPPORTED_ABIS.firstOrNull()} debuggable=${debuggable()}",
        )
        // After the line, so a run over the bound still says what it measured.
        assertTrue(
            "the cold verification took ${cold.first} ms, over the $COLD_BOUND_MS ms bound",
            cold.first <= COLD_BOUND_MS,
        )
    }

    private fun <T> timed(block: () -> T): Pair<Long, T> {
        val start = System.nanoTime()
        val result = block()
        return (System.nanoTime() - start) / 1_000_000 to result
    }

    private fun debuggable(): Boolean {
        val flags = InstrumentationRegistry.getInstrumentation().targetContext.applicationInfo.flags
        return flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    }

    /** A hex fixture from icrc167-canister-sig's test resources, which this test shares. */
    private fun vector(name: String): ByteArray {
        val stream = checkNotNull(javaClass.getResourceAsStream("/vectors/$name.hex")) {
            "missing test vector $name: is icrc167-canister-sig/src/test/resources on the androidTest resources path?"
        }
        val text = stream.use { it.readBytes() }.toString(Charsets.UTF_8).filter { !it.isWhitespace() }
        check(text.isNotEmpty() && text.length % 2 == 0) { "test vector $name is not a whole number of bytes" }
        return ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private companion object {
        const val TAG = "ICRC167_TIMING"
        const val WARM_RUNS = 5

        /**
         * Three times the slowest cold run measured on the device job (x86_64, API 34, a
         * debuggable build) on 2026-09-11: 381, 721 and 1118 ms in runs 34572794726,
         * 34572827763 and 34572820586. The spread between CI hosts is itself close to threefold.
         */
        const val COLD_BOUND_MS = 3354L
    }
}
