import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    kotlin("jvm") version "2.3.0"
    id("com.gradleup.shadow") version "9.0.0-beta12"
}

group = "at.bestsolution"
version = "0.1.0"

repositories {
    mavenCentral()
    maven("https://maven.reposilite.com/releases")
    maven("https://maven.reposilite.com/snapshots")
}

dependencies {
    // Reposilite — provided at runtime by the container
    compileOnly("com.reposilite:reposilite-backend:3.5.26")

    // JWT verification — bundled in the fat JAR
    implementation("com.nimbusds:nimbus-jose-jwt:10.0.2")

    // Test dependencies
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testImplementation("com.reposilite:reposilite-backend:3.5.26")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        // Target JVM 11 for Reposilite compatibility
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        // Use Kotlin 2.2 language level for binary compatibility with Reposilite 3.5.26
        languageVersion.set(KotlinVersion.KOTLIN_2_2)
        apiVersion.set(KotlinVersion.KOTLIN_2_2)
    }
}

tasks.test {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveClassifier.set("")
    mergeServiceFiles()
}

// Make the default jar task produce the shadow JAR
tasks.jar {
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
