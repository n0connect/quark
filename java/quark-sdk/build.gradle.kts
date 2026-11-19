// quark-sdk.jar -- developer-facing compile-time dependency.
// No runtime dependencies; the real QuarkRuntime runs from quark.jar.

plugins {
    id("java")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.jar {
    archiveBaseName.set("quark-sdk")
    archiveVersion.set("")
}
