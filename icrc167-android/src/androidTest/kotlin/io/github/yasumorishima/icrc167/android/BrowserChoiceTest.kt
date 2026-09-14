package io.github.yasumorishima.icrc167.android

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.yasumorishima.icrc167.Icrc167
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Declared in this test's manifest; it claims the signer's URL and is never started. */
class SignerWebAppStandIn : Activity()

/**
 * The sign-in page must reach a browser even when another app claims the signer's URL.
 *
 * On a real phone, Internet Identity installed as a web app by Chrome took both the Custom Tab
 * and a plain browser intent, and the passkey prompt never came. This test's manifest declares an
 * activity that claims the same URL, so the device holds the same kind of claimant.
 */
@RunWith(AndroidJUnit4::class)
class BrowserChoiceTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext

    @After
    fun cleanUp() {
        Icrc167Client(context, Callbacks.URL).signOut()
    }

    /** Every package Android would hand this intent to. */
    private fun takers(intent: Intent): Set<String> {
        @Suppress("DEPRECATION")
        val found = context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
        return found.map { it.activityInfo.packageName }.toSet()
    }

    @Test
    fun launchAddressesTheTabToABrowserNotToTheSignersWebApp() {
        // Below 30 every app sees every other, and the library's <queries> would go untested.
        assertTrue(
            "target SDK " + context.applicationInfo.targetSdkVersion + " does not exercise package visibility",
            context.applicationInfo.targetSdkVersion >= 30,
        )
        val browser = preferredBrowserPackage(context)
        assertNotNull("no browser is visible to the library", browser)
        assertNotEquals("the claimant was taken for a browser", context.packageName, browser)

        val sent = AtomicReference<Intent>()
        val monitor = object : Instrumentation.ActivityMonitor() {
            override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult? {
                if (intent.action != Intent.ACTION_VIEW) return null
                sent.set(Intent(intent))
                // Not null, so nothing is actually started.
                return Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null)
            }
        }
        instrumentation.addMonitor(monitor)
        try {
            Icrc167Client(context, Callbacks.URL).launch(NewTask(context))
        } finally {
            instrumentation.removeMonitor(monitor)
        }
        val tab = sent.get() ?: throw AssertionError("launch started no activity")

        assertEquals(Uri.parse(Icrc167.INTERNET_IDENTITY_URL).host, tab.data?.host)
        assertEquals(browser, tab.`package`)
        assertEquals(setOf(browser), takers(tab))

        // The control: the same intent without the address does reach the claimant, so the
        // assertion above is what the address changed and not a claimant that never matched.
        val unaddressed = Intent(tab).setPackage(null)
        assertTrue(
            "the stand-in does not claim " + tab.data + "; takers " + takers(unaddressed),
            context.packageName in takers(unaddressed),
        )
    }

    /** The application context can only start an activity into a new task. */
    private class NewTask(base: Context) : ContextWrapper(base) {
        override fun startActivity(intent: Intent) {
            super.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }

        override fun startActivity(intent: Intent, options: Bundle?) {
            super.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), options)
        }
    }
}
