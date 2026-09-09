plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
    explicitApi()
}

// MIRACL Core, vendored rather than pulled from Maven: there is no BLS12-381 artifact there
// with this curve configuration, and the two that come close implement a different arrangement
// of the groups. Kept in its own source root so the boundary between what upstream generated
// and what this repository wrote stays visible. Regenerate with scripts/vendor-miracl.sh —
// do not hand-edit.
sourceSets["main"].java.srcDir("src/miracl/java")

dependencies {
    api(project(":icrc167-core"))
    api(project(":icrc167-certificate"))

    testImplementation(kotlin("test"))
    // The end-to-end tests check that a whole Internet Identity chain verifies, which needs
    // the verifier for the schemes this one deliberately does not handle.
    testImplementation(project(":icrc167-crypto"))
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
    }
}
