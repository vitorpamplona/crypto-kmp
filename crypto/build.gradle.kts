import com.vanniktech.maven.publish.KotlinMultiplatform
import com.vanniktech.maven.publish.SourcesJar
import org.jetbrains.kotlin.gradle.ExperimentalWasmDsl
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidKotlinMultiplatformLibrary)
    alias(libs.plugins.vanniktech.mavenPublish)
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

mavenPublishing {
    configure(
        KotlinMultiplatform(
            sourcesJar = SourcesJar.Sources(),
        ),
    )

    // groupId, artifactId, and version are configured via gradle.properties
    // (GROUP, POM_ARTIFACT_ID, VERSION_NAME) so CI can override VERSION_NAME
    // via ORG_GRADLE_PROJECT_VERSION_NAME without conflicting with a hardcoded value.

    publishToMavenCentral(automaticRelease = true)

    // Sign only when a key is configured: the release workflow passes one, while JitPack and
    // local publishToMavenLocal builds have none and would otherwise fail on the signing task.
    // Maven Central still rejects an unsigned upload, so a release can't slip out unsigned.
    if (providers.gradleProperty("signingInMemoryKey").isPresent) {
        signAllPublications()
    }

    pom {
        name = "Crypto for Kotlin Multiplatform"
        description =
            "Pure-Kotlin and platform-backed SHA-1/2, HMAC, HKDF, AES-GCM/CBC, ChaCha20-Poly1305, " +
            "X25519 and Ed25519 for JVM, Android, iOS, macOS, Linux, JavaScript and Wasm"
        inceptionYear = "2026"
        url = "https://github.com/vitorpamplona/crypto-kmp/"
        licenses {
            license {
                name = "MIT License"
                url = "https://github.com/vitorpamplona/crypto-kmp/blob/main/LICENSE"
            }
        }
        developers {
            developer {
                id = "vitorpamplona"
                name = "Vitor Pamplona"
                url = "http://vitorpamplona.com"
                email = "vitor@vitorpamplona.com"
            }
        }
        scm {
            url = "https://github.com/vitorpamplona/crypto-kmp"
            connection = "https://github.com/vitorpamplona/crypto-kmp.git"
        }
    }
}
