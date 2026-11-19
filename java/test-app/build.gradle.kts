plugins {
    java
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    compileOnly(project(":quark-sdk"))
}

tasks.jar {
    archiveFileName.set("test-app.jar")
}
