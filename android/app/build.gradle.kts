plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.denkikun.kizuna"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.denkikun.kizuna"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // Only for JVM unit tests; the app itself has no third-party dependencies.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
