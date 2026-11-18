pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "crypto-kmp"
include(":crypto")

// Not published: JMH and benchmark.js runs against JCA, Bouncy Castle, noble and node:crypto.
include(":benchmark")

// Not published either: Jetpack Microbenchmark on a device, against Android's JCA and Bouncy Castle.
include(":benchmark-android")
