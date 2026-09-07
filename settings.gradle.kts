pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "icrc167"

include(":icrc167-core")
include(":icrc167-crypto")
include(":icrc167-android")
include(":probe")
