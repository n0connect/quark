// quark-build -- bundle builder for Quark DRM.
// Reads a JAR, packs all class files into the InMemoryClassLoader bundle format,
// outputs app.bundle (to be encrypted by dev_keygen --input-bundle).

plugins {
    id("java")
    id("application")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

application {
    mainClass.set("quark.build.QuarkBuild")
}

tasks.jar {
    archiveBaseName.set("quark-build")
    archiveVersion.set("")
    manifest {
        attributes["Main-Class"] = "quark.build.QuarkBuild"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
