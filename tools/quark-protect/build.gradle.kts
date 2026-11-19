// quark-protect -- bytecode transformer for Quark DRM.
// Scans @QuarkCheckpoint-annotated methods in a JAR and injects diversified
// QuarkRuntime.checkpoint(id) calls that feed into surrounding business logic.
// Uses ASM 9 for bytecode manipulation.

plugins {
    id("java")
    id("application")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

repositories {
    mavenCentral()
}

dependencies {
    // ASM for bytecode manipulation -- no other runtime deps
    implementation("org.ow2.asm:asm:9.6")
    implementation("org.ow2.asm:asm-commons:9.6")
}

application {
    mainClass.set("quark.protect.QuarkProtect")
}

// Fat JAR: bundle ASM so the tool is self-contained
tasks.jar {
    archiveBaseName.set("quark-protect")
    archiveVersion.set("")
    manifest {
        attributes["Main-Class"] = "quark.protect.QuarkProtect"
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
