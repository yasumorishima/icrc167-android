package io.github.yasumorishima.icrc167.demo

import android.content.pm.PackageManager

/** Said in place of a build, so that "not read" and "has no version" do not look alike. */
internal const val BUILD_UNREADABLE: String = "(build not readable)"

/**
 * Which app the sign-in page was sent to, and which build of it.
 *
 * The build belongs on the line because it is what decides the outcome. A sign-in that stalled
 * on a phone on 2026-09-15 stalled in the browser and not in this app: Chromium filled the
 * transports an omitting page had left empty with smart-card, Play services could not read
 * that, and the request never came back. The change that stops Chromium sending it reached
 * stable Android in 153.0.8010.47, and every Chromium browser takes that on its own schedule.
 * A run that names only the package therefore cannot say afterwards which of the two it met.
 *
 * The line is composed before the tab opens, so it is already on the screen when a sign-in
 * never comes back.
 */
internal fun browserLine(packages: PackageManager, browser: String?): String {
    if (browser == null) return "OPEN  no browser visible, so Android chooses"
    // Not installed, or not visible to this app, and getPackageInfo throws rather than
    // returning null for either. versionName is nullable in its own right.
    val build = runCatching { packages.getPackageInfo(browser, 0).versionName }.getOrNull()
    return "OPEN  " + browser + " " + (build ?: BUILD_UNREADABLE)
}
