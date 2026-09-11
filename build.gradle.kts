plugins {
    kotlin("jvm") version "2.4.20" apply false
    // Android Gradle plugin 9 compiles Kotlin itself (built-in Kotlin), so the Android modules
    // no longer apply kotlin("android"). 9.4 needs Gradle 9.6.0 or later and JDK 17;
    // androidx.browser 1.10.0 declares 8.9.1 as its floor.
    id("com.android.application") version "9.4.0" apply false
    id("com.android.library") version "9.4.0" apply false
}
