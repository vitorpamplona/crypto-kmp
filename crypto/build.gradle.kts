import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    `maven-publish`
    // Releases: publishToNostr. Its relays come from gradle.properties (magpie.*).
    alias(libs.plugins.magpiePublish)
}

kotlin {
    // A library: every public declaration is a choice, and the ABI dump in api/ records it,
    // so a breaking change shows up in review (and in a major version) instead of by accident.
    explicitApi()

    @OptIn(ExperimentalAbiValidation::class)
    abiValidation()

    compilerOptions {
        freeCompilerArgs.add("-Xexpect-actual-classes")
    }

    // JVM 17: Quartz, the main consumer, targets 17, and a dependency can't need a newer JVM
    // than the library that uses it.
    jvm {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    android {
        namespace = "com.vitorpamplona.crypto"
        compileSdk =
            libs.versions.android.compileSdk
                .get()
                .toInt()
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }

        withHostTest {}

        // commonTest again, on a device or emulator: ART, and Android's own providers
        // (AndroidOpenSSL, BoringSSL) behind JCA, which the host tests' desktop JVM doesn't have.
        // In the "test" tree, so it compiles commonTest like the host tests do.
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    iosArm64()
    iosSimulatorArm64()
    macosArm64()
    linuxX64()

    // The web: Kotlin everywhere, with crypto.getRandomValues for entropy. Web Crypto's
    // digests and ciphers are async-only, so they can't sit behind this synchronous API.
    js {
        browser()
        // Kotlin/JS emulates Long, so the Curve25519 tests that run thousands of scalar
        // multiplications take minutes there; Mocha's default would stop each after 2s.
        // karma.config.d/ raises the browser's limits to match.
        nodejs { testTask { useMocha { timeout = "10m" } } }
    }

    @OptIn(ExperimentalWasmDsl::class)
    wasmJs {
        browser()
        nodejs()
    }

    sourceSets {
        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }

        // JCA on the JVM and on Android.
        val jvmAndroid =
            create("jvmAndroid") {
                dependsOn(commonMain.get())
            }

        jvmMain {
            dependsOn(jvmAndroid)
        }

        androidMain {
            dependsOn(jvmAndroid)
        }

        val jvmAndroidTest =
            create("jvmAndroidTest") {
                dependsOn(commonTest.get())
            }

        jvmTest {
            dependsOn(jvmAndroidTest)
        }

        getByName("androidHostTest") {
            dependsOn(jvmAndroidTest)
            dependencies {
                implementation(libs.kotlin.test)
            }
        }

        getByName("androidDeviceTest") {
            dependsOn(jvmAndroidTest)
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.androidx.test.runner)
                implementation(libs.androidx.test.junit)
            }
        }

        // Kotlin implementations shared by every target but the JVM and Android; appleMain
        // swaps in CommonCrypto where it has the algorithm.
        val nonJvmMain =
            create("nonJvmMain") {
                dependsOn(commonMain.get())
            }

        val nonJvmTest =
            create("nonJvmTest") {
                dependsOn(commonTest.get())
            }

        val appleMain =
            create("appleMain") {
                dependsOn(nonJvmMain)
            }

        val appleTest =
            create("appleTest") {
                dependsOn(nonJvmTest)
            }

        // The Kotlin digests, HMAC and AES-CBC, for the targets with no platform library to
        // call: Linux and the web. Each of those brings only its entropy source.
        val portableMain =
            create("portableMain") {
                dependsOn(nonJvmMain)
            }

        val portableTest =
            create("portableTest") {
                dependsOn(nonJvmTest)
            }

        val linuxMain =
            create("linuxMain") {
                dependsOn(portableMain)
            }

        val linuxTest =
            create("linuxTest") {
                dependsOn(portableTest)
            }

        listOf("iosArm64", "iosSimulatorArm64", "macosArm64").forEach { target ->
            getByName("${target}Main") { dependsOn(appleMain) }
            getByName("${target}Test") { dependsOn(appleTest) }
        }

        getByName("linuxX64Main") { dependsOn(linuxMain) }
        getByName("linuxX64Test") { dependsOn(linuxTest) }

        listOf("js", "wasmJs").forEach { target ->
            getByName("${target}Main") { dependsOn(portableMain) }
            getByName("${target}Test") { dependsOn(portableTest) }
        }
    }
}

// Releases go to Nostr + Blossom through Magpie (https://github.com/vitorpamplona/magpie), which
// reuses this maven-publish setup: publishToNostr publishes these same publications into
// build/magpie-repo, uploads the files to Blossom and signs one release event for all of them.
// The coordinates stay com.vitorpamplona.crypto:crypto(-<target>), from gradle.properties, and
// are set on the publications only: the project's group names the klibs (crypto-kmp:crypto), and
// changing it would change their ABI.
publishing {
    publications.withType<MavenPublication>().configureEach {
        groupId = providers.gradleProperty("GROUP").get()
        version = providers.gradleProperty("VERSION_NAME").get()
        pom {
            name.set("Crypto for Kotlin Multiplatform")
            description.set(
                "Pure-Kotlin and platform-backed SHA-1/2, HMAC, HKDF, AES-GCM/CBC, ChaCha20-Poly1305, " +
                    "X25519 and Ed25519 for JVM, Android, iOS, macOS, Linux, JavaScript and Wasm",
            )
            inceptionYear.set("2026")
            url.set("https://github.com/vitorpamplona/crypto-kmp/")
            licenses {
                license {
                    name.set("MIT License")
                    url.set("https://github.com/vitorpamplona/crypto-kmp/blob/main/LICENSE")
                }
            }
            developers {
                developer {
                    id.set("vitorpamplona")
                    name.set("Vitor Pamplona")
                    url.set("http://vitorpamplona.com")
                    email.set("vitor@vitorpamplona.com")
                }
            }
            scm {
                url.set("https://github.com/vitorpamplona/crypto-kmp")
                connection.set("https://github.com/vitorpamplona/crypto-kmp.git")
            }
        }
    }
}
