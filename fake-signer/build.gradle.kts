plugins {
    kotlin("jvm")
    application
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":icrc167-core"))
    implementation("org.json:json:20240303")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
}

application {
    mainClass.set("io.github.yasumorishima.icrc167.fakesigner.MainKt")
}
