plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    // Deliberately dependency-free. Everything here is parsing and SHA-256, and the input is
    // attacker-supplied, so there is nothing to gain from pulling a general-purpose CBOR
    // library that accepts far more than a certificate ever contains.
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
}
