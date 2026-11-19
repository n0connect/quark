// Builds main.jar -- the ordinary part of the protected application.
//
// What does NOT belong here: quark.app.CoreEntryPoint and any sibling classes
// that hold the actual protected business logic. Those get compiled normally,
// then packed into the encrypted core.enc bundle (see docs/PLAN.md Phase III)
// and stripped from this jar -- main.jar should be able to ship without them
// and merely fail to find quark.app.CoreEntryPoint until quark.jar supplies it
// from memory at runtime.

plugins {
    id("java")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

tasks.jar {
    archiveBaseName.set("main")
    archiveVersion.set("")
}
