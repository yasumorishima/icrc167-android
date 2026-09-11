plugins {
    id("com.android.application")
}

android {
    namespace = "io.github.yasumorishima.icrc167.probe"
    // androidx.browser 1.10.0 refuses to be compiled against anything older.
    compileSdk = 36

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

dependencies {
    implementation(project(":icrc167-android"))
}
