plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    // The core carries Principal, ReprHash and the delegation model. The certificate module
    // is here because a query response is only worth what its signature is worth, and
    // checking that means reading node keys out of a certified state tree. It stays
    // dependency-free itself, and the BLS arithmetic behind it is still injected, so an app
    // that never verifies a response does not ship MIRACL.
    api(project(":icrc167-core"))
    api(project(":icrc167-certificate"))

    testImplementation(kotlin("test"))
    testImplementation(project(":icrc167-crypto"))
    // The real pairing, so the recorded certificate is checked to the mainnet root key rather
    // than to a stub.
    testImplementation(project(":icrc167-canister-sig"))
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
}

tasks.test {
    useJUnitPlatform()
    // The live round trip talks to mainnet, so it only runs when it is asked for.
    systemProperty("icrc167.live", System.getProperty("icrc167.live") ?: "")
    testLogging {
        events("passed", "failed", "skipped")
    }
}
