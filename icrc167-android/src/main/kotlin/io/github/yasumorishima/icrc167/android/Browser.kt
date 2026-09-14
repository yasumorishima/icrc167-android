package io.github.yasumorishima.icrc167.android

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import androidx.browser.customtabs.CustomTabsService

/**
 * The browser a sign-in should open in: the user's default browser when there is one; otherwise a
 * browser that supports Custom Tabs, preferring one that came with the system; otherwise any
 * browser. Null when no browser can be seen.
 *
 * Why name a browser at all. On a phone where Chrome had installed Internet Identity as a web app
 * (a WebAPK), the sign-in page opened in that web app and the passkey prompt never appeared. Two
 * things can move a link there, and an intent addressed to a browser's package stops both:
 * - Android resolves an unaddressed link against every app approved for the site. An addressed
 *   intent is only resolved against that package.
 * - A Chromium browser that receives a link from another app hands it to a WebAPK for the site
 *   from Android 12 on, unless the intent named the browser's own package, which it takes as
 *   the app wanting the browser (`ExternalNavigationHandler` and `RedirectHandler` in Chromium's
 *   components/external_intents, as of September 2026). That is read from the source, not
 *   observed on the phone.
 *
 * Browsers are found with a link that has a scheme and no host. A browser handles every such
 * link; an app that claims particular sites, which is what an installed web app is, handles none.
 * With no default chosen, the system's own browsers come first so that an app merely declaring
 * itself a browser is not picked silently where Android would have asked.
 *
 * On Android 11 and later this depends on the `<queries>` this library's manifest declares, which
 * is merged into the app's.
 */
public fun preferredBrowserPackage(context: Context): String? {
    val packages = context.packageManager
    val anyWebLink = Intent(Intent.ACTION_VIEW, Uri.parse("https://"))
        .addCategory(Intent.CATEGORY_BROWSABLE)

    @Suppress("DEPRECATION") // The flag-object overload only exists from API 33.
    val browsers = packages.queryIntentActivities(anyWebLink, PackageManager.MATCH_DEFAULT_ONLY)
        .map { it.activityInfo.packageName }
        .distinct()
    if (browsers.isEmpty()) return null

    // With no default chosen this resolves to the system's chooser, which is not in the list.
    @Suppress("DEPRECATION")
    val default = packages.resolveActivity(anyWebLink, PackageManager.MATCH_DEFAULT_ONLY)
        ?.activityInfo?.packageName
    if (default != null && default in browsers) return default

    @Suppress("DEPRECATION")
    val customTabs = packages.queryIntentServices(Intent(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION), 0)
        .map { it.serviceInfo.packageName }
        .toSet()
    val system = browsers.filter { name ->
        val flags = runCatching { packages.getApplicationInfo(name, 0).flags }.getOrDefault(0)
        flags and ApplicationInfo.FLAG_SYSTEM != 0
    }.toSet()
    return browsers.firstOrNull { it in customTabs && it in system }
        ?: browsers.firstOrNull { it in customTabs }
        ?: browsers.first()
}
