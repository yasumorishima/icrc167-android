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
include(":icrc167-certificate")
include(":icrc167-canister-sig")
include(":icrc167-agent")
include(":icrc167-android")
include(":probe")
include(":demo")
include(":fake-signer")
