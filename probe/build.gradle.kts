plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "io.github.yasumorishima.icrc167.probe"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.github.yasumorishima.icrc167.probe"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}
