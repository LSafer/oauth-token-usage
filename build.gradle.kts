plugins {
    `maven-publish`
    kotlin("multiplatform") version "1.9.20"
    kotlin("plugin.serialization") version "1.9.20"
}

group = "net.lsafer"
version = "1.0.0-snapshot"

tasks.wrapper {
    gradleVersion = "8.2.1"
}

repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

kotlin {
    jvm {
        withJava()
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(kotlin("stdlib"))
                implementation(kotlin("reflect"))

                implementation("io.ktor:ktor-server-core:2.3.7")
                implementation("io.ktor:ktor-server-auth:2.3.7")
                implementation("net.lsafer.oidc-spec:oauth:1.0.0-RC.2")
            }
        }
        commonTest {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}
