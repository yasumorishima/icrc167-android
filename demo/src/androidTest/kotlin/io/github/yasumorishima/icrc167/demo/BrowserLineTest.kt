package io.github.yasumorishima.icrc167.demo

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.yasumorishima.icrc167.android.preferredBrowserPackage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The OPEN line has to name the browser's build, because that is what a sign-in which never
 * comes back is read against afterwards.
 *
 * These run on a device because package visibility is an Android rule: from API 30 an app is
 * shown only what its manifest says it looks for, and reading a version out of a package the
 * rule hides is exactly the case the line has to survive.
 *
 * What they do not cover: that DemoActivity prints this line rather than composing one of its
 * own. Re-inlining the string at either call site would leave all three of these green, and
 * that is the only output a stalled phone actually shows.
 */
@RunWith(AndroidJUnit4::class)
class BrowserLineTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun theLineCarriesTheBuildOfTheBrowserThatWouldBeOpened() {
        val browser = preferredBrowserPackage(context)
        assertNotNull("no browser is visible, so this test would prove nothing", browser)
        // The whole line is pinned, not just that something follows the package. A line ending
        // in the version code, or the app's label, would satisfy "some non-empty tail" while
        // saying nothing about the build, which is the one thing this line exists to carry.
        @Suppress("DEPRECATION") // The flags-object overload only exists from API 33.
        val build = context.packageManager.getPackageInfo(browser!!, 0).versionName
        assertNotNull("this browser declares no versionName, so the test would prove nothing", build)
        assertEquals(
            "OPEN  " + browser + " " + build,
            browserLine(context.packageManager, browser),
        )
    }

    /** The one case the line exists to survive: it degrades rather than throwing. */
    @Test
    fun aPackageThatIsNotThereIsSaidSoRatherThanThrowing() {
        val absent = "io.github.yasumorishima.icrc167.absent"
        assertEquals(
            "OPEN  " + absent + " " + BUILD_UNREADABLE,
            browserLine(context.packageManager, absent),
        )
    }

    /** No browser at all is a different thing from a browser whose build cannot be read. */
    @Test
    fun noBrowserAtAllIsItsOwnLine() {
        assertEquals(
            "OPEN  no browser visible, so Android chooses",
            browserLine(context.packageManager, null),
        )
    }
}
