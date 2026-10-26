import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Benchmarks of :crypto against the other libraries on each platform. Nothing here is
// published, so the comparison libraries never reach the library's users.
plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.kotlinAllOpen)
    alias(libs.plugins.kotlinxBenchmark)
}

// JMH subclasses @State classes, and Kotlin classes are final.
allOpen {
    annotation("org.openjdk.jmh.annotations.State")
}

kotlin {
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    js {
        // As in :crypto: Kotlin/JS emulates Long, and its AES-GCM and Curve25519 checks in
        // SameOutputJsTest can outlast Mocha's default 2s.
        nodejs { testTask { useMocha { timeout = "10m" } } }
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        nodejs()
    }

    sourceSets {
        commonMain {
            dependencies {
                implementation(project(":crypto"))
                implementation(libs.kotlinx.benchmark.runtime)
            }
        }

        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }

        jvmMain {
            dependencies {
                implementation(libs.bouncycastle)
            }
        }

        // noble is the reference pure-JavaScript implementation, and TweetNaCl the old
        // standby; node:crypto (OpenSSL) needs no package.
        jsMain {
            dependencies {
                implementation(npm("@noble/hashes", "2.4.0"))
                implementation(npm("@noble/ciphers", "2.4.0"))
                implementation(npm("@noble/curves", "2.4.0"))
                implementation(npm("tweetnacl", "1.0.3"))
            }
        }
    }
}

benchmark {
    targets {
        register("jvm")
        register("js")
        register("wasmJs")
    }

    configurations {
        // Average time per operation, in microseconds: the same unit on every platform.
        named("main") {
            mode = "avgt"
            outputTimeUnit = "us"
            warmups = 3
            iterations = 5
            iterationTime = 1
            iterationTimeUnit = "s"
        }

        // A fast pass to check every benchmark runs; its numbers are too noisy to compare.
        register("smoke") {
            mode = "avgt"
            outputTimeUnit = "us"
            warmups = 1
            iterations = 1
            iterationTime = 200
            iterationTimeUnit = "ms"
        }
    }
}
