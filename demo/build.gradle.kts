plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.yasumorishima.icrc167.demo"
    // androidx.browser 1.10.0 refuses to be compiled against anything older.
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.yasumorishima.icrc167.demo"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
        // BrowserLine reads a version out of another app's package, which only means anything
        // under Android's package-visibility rule, so its tests have to run on a device.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // The callback only reaches this app if Android can match the certificate the APK is
    // signed with against the fingerprint in the callback origin's assetlinks.json. A debug
    // key differs from machine to machine, so the release build is signed with one fixed key
    // that CI hands in. Without it the release build stays unsigned rather than being signed
    // with a key that could never match.
    val keystore = System.getenv("DEMO_KEYSTORE_PATH")
    if (!keystore.isNullOrEmpty()) {
        signingConfigs {
            create("demo") {
                storeFile = file(keystore)
                storeType = "pkcs12"
                storePassword = System.getenv("DEMO_KEYSTORE_PASSWORD")
                keyAlias = "demo"
                keyPassword = System.getenv("DEMO_KEYSTORE_PASSWORD")
            }
        }
        buildTypes.getByName("release").signingConfig = signingConfigs.getByName("demo")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":icrc167-android"))
    implementation(project(":icrc167-agent"))

    // The demo's own device tests. Held to the versions the library module already uses, so
    // the emulator installs one runner and not two.
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
