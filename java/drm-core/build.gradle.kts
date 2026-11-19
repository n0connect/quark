// Builds quark.jar -- the bridge DRM_Wrapper.exe hands its handoff token to.
//
// Deliberately dependency-free (matches the C++ side's "zero external
// dependencies" stance): javax.crypto (JCE, built into the JDK) covers
// AES-256-GCM, and the bundled bootstrap classes need nothing else. Any
// third-party dependency here would be one more thing to vet for the same
// "can this be hooked/substituted" questions the C++ side asks of mbedTLS.

plugins {
    id("java")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.jar {
    archiveBaseName.set("quark")
    archiveVersion.set("")
    manifest {
        attributes["Main-Class"] = "quark.drmcore.Bootstrap"
    }
}
