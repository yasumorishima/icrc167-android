package io.github.yasumorishima.icrc167.android

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.yasumorishima.icrc167.Icrc167
import java.util.concurrent.atomic.AtomicReference
import org.junit.After
import org.junit.Before
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Declared in this test's manifest; it claims the signer's URL and is never started. */
class SignerWebAppStandIn : Activity()

/**
 * The sign-in page must reach the chosen browser even when another app is approved for the
 * signer's site.
 *
 * This covers Android's part of the routing only. The web app that took the page on a real phone
 * may instead have been reached through the browser, which a device test here cannot reproduce
 * because it cannot install a WebAPK; see [preferredBrowserPackage].
 *
 * The approval matters: on API 34 an app that only declares the URL, neither verified nor
 * approved, is not offered web links at all. The first run of this test measured that, when its
 * control found only the browser.
 */
@RunWith(AndroidJUnit4::class)
class BrowserChoiceTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context = instrumentation.targetContext

    @Before
    fun approveTheClaimant() = approveSignerLink(true)

    @After
    fun cleanUp() {
        approveSignerLink(false)
        Icrc167Client(context, Callbacks.URL).signOut()
    }

    /** What a user, or the installer of a web app, does to let an app open a site's links. */
    private fun approveSignerLink(approved: Boolean) {
        assertTrue("link approval needs API 31, this is " + Build.VERSION.SDK_INT, Build.VERSION.SDK_INT >= 31)
        val host = Uri.parse(Icrc167.INTERNET_IDENTITY_URL).host
        val command = "pm set-app-links-user-selection --user 0 --package " + context.packageName +
            " " + approved + " " + host
        val output = instrumentation.uiAutomation.executeShellCommand(command)
        ParcelFileDescriptor.AutoCloseInputStream(output).use { it.readBytes() }
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
            "the stand-in does not take the signer's URL; takers " + takers(unaddressed),
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
