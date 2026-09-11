plugins {
    kotlin("jvm") version "2.4.20" apply false
    kotlin("android") version "2.4.20" apply false
    // 8.9.1 is the floor androidx.browser 1.10.0 declares; this is the current 8.x.
    id("com.android.application") version "8.13.2" apply false
    id("com.android.library") version "9.4.0" apply false
}
