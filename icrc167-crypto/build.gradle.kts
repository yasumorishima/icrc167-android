plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

dependencies {
    api(project(":icrc167-core"))

    // Bouncy Castle rather than JCA: Ed25519 only reaches Android's JCA at API 33, and this
    // library targets lower. The low-level (`org.bouncycastle.crypto`) API is used directly,
    // so nothing has to be registered as a security provider on the consumer's behalf.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    testImplementation(kotlin("test"))
    testImplementation("org.bouncycastle:bcutil-jdk18on:1.78.1")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
}
