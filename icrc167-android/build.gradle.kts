plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "io.github.yasumorishima.icrc167.android"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    api(project(":icrc167-core"))
    api(project(":icrc167-crypto"))

    // Custom Tabs: the authorisation page must run in the user's browser, where the passkey
    // and any existing Internet Identity session already live. A WebView would see neither.
    implementation("androidx.browser:browser:1.8.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
}
