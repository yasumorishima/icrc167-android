plugins {
    id("com.android.application")
    kotlin("android")
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
}
