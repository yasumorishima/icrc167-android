package io.github.yasumorishima.icrc167.demo

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.yasumorishima.icrc167.android.preferredBrowserPackage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The OPEN line has to name the browser's build, because that is what a sign-in which never
 * comes back is read against afterwards.
 *
 * These run on a device rather than the JVM because package visibility is an Android rule: from
 * API 30 an app is shown only what its manifest says it looks for, and reading a version out of
 * a package that the rule hides is exactly the case the line has to survive.
 */
@RunWith(AndroidJUnit4::class)
class BrowserLineTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun theLineCarriesTheBuildOfTheBrowserThatWouldBeOpened() {
        val browser = preferredBrowserPackage(context)
        assertNotNull("no browser is visible, so this test would prove nothing", browser)
        val line = browserLine(context.packageManager, browser)
        assertTrue("the package is not named in " + line, line.contains(browser!!))
        assertFalse("the build was not read: " + line, line.contains(BUILD_UNREADABLE))
        val build = line.substringAfter(browser).trim()
        assertTrue("nothing follows the package in " + line, build.isNotEmpty())
    }

    /** The one case the line exists to survive: it degrades rather than throwing. */
    @Test
    fun aPackageThatIsNotThereIsSaidSoRatherThanThrowing() {
        val line = browserLine(context.packageManager, "io.github.yasumorishima.icrc167.absent")
        assertEquals("OPEN  io.github.yasumorishima.icrc167.absent " + BUILD_UNREADABLE, line)
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
