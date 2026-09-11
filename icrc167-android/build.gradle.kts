plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "io.github.yasumorishima.icrc167.android"
    // androidx.browser 1.10.0 refuses to be compiled against anything older.
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        // The client needs a real Context, real preferences and the Android Keystore, none of
        // which a JVM unit test has, so its tests run on a device.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    // Every Internet Identity chain is signed at its root by a canister signature, so an app
    // that signs in with Internet Identity cannot do without this. It stays a module of its
    // own for JVM code that checks no certificates at all.
    api(project(":icrc167-canister-sig"))

    // Custom Tabs: the authorisation page must run in the user's browser, where the passkey
    // and any existing Internet Identity session already live. A WebView would see neither.
    implementation("androidx.browser:browser:1.10.0")
    implementation("org.bouncycastle:bcprov-jdk18on:1.85.2")

    // The device tests sign their own delegations with the BouncyCastle above.
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
