plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    // Only the core: this module has to stay usable from an Android app, and everything it
    // needs beyond the JDK (Principal, ReprHash, the delegation model) already lives there.
    // The CBOR codec here is deliberately not the certificate module one -- see AgentCbor.
    api(project(":icrc167-core"))

    testImplementation(kotlin("test"))
    testImplementation(project(":icrc167-crypto"))
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
