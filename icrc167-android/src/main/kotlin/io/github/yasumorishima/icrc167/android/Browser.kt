package io.github.yasumorishima.icrc167.android

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import androidx.browser.customtabs.CustomTabsService

/**
 * The browser a sign-in should open in: the user's default browser when there is one, otherwise
 * a browser that supports Custom Tabs, otherwise any browser. Null when no browser can be seen.
 *
 * Why name a browser at all: an intent for the signer's URL is resolved against every app that
 * claims that URL, and an installed web app of the signer is one of them. On a phone where Chrome
 * had installed Internet Identity as a web app, the Custom Tab and a plain browser intent both
 * opened in that web app, and the passkey prompt never appeared. An intent addressed to a browser
 * by package can only go to that browser.
 *
 * Browsers are found with a link that has a scheme and no host. A browser handles every such
 * link; an app that claims particular sites, which is what an installed web app is, handles none.
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
    return browsers.firstOrNull { it in customTabs } ?: browsers.first()
}
