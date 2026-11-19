plugins {
    java
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.jar {
    archiveFileName.set("e2e-test.jar")
    manifest {
        attributes["Main-Class"] = "quark.test.QuarkE2ETest"
    }
    // Fat JAR: no external dependencies, so this is just the compiled class files.
}
