plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    // `org.json` is part of the Android platform, so it is compileOnly here: an Android
    // consumer must not bundle a second copy. On a plain JVM, add org.json:json yourself.
    // Signature verification is injected (see SignatureVerifier), so the core needs no
    // crypto provider of its own and stays usable on Android as-is.
    compileOnly("org.json:json:20240303")

    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20240303")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
}
