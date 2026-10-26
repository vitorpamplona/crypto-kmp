// Jetpack Microbenchmark on a device: :crypto against Android's own JCA (AndroidOpenSSL, which
// is BoringSSL) and Bouncy Castle, the same operations as :benchmark. Nothing here is published.
//
//   ./gradlew :benchmark-android:connectedReleaseAndroidTest    # a physical device, for numbers
//
// Microbenchmark refuses an emulator, a debuggable build or a low battery, because their numbers
// mean little; CI runs it on an emulator in dry-run mode only, to check every benchmark runs.
plugins {
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.androidxBenchmark)
}

android {
    namespace = "com.vitorpamplona.crypto.benchmark.android"
    compileSdk =
        libs.versions.android.compileSdk
            .get()
            .toInt()

    defaultConfig {
        minSdk =
            libs.versions.android.minSdk
                .get()
                .toInt()
        testInstrumentationRunner = "androidx.benchmark.junit4.AndroidBenchmarkRunner"
    }

    // Measure release code: a debuggable APK runs ART with its optimisations held back.
    testBuildType = "release"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    androidTestImplementation(project(":crypto"))
    androidTestImplementation(libs.androidx.benchmark.junit4)
    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.bouncycastle)
    androidTestImplementation(libs.kotlin.test)
}
