import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

android {
    // The instrumentation tests use the platform's legacy runner.
    useLibrary("android.test.runner")
    useLibrary("android.test.base")
    useLibrary("android.test.mock")
    compileSdk = 35
    // The SDK scripts/setup-android.sh installs (platform 35, build tools 35.0.0).
    buildToolsVersion = "35.0.0"
    namespace = "org.quickvault.app"
    defaultConfig {
        applicationId = "org.quickvault.app"
        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
        // QR camera scanning (0009 §1.7) is on by default (owner 2026-11-07);
        // `-PqvQrCamera=false` builds a package without it.
        buildConfigField("boolean", "QR_CAMERA", (findProperty("qvQrCamera") ?: "true").toString())
        minSdk = 29
        targetSdk = 35
        // scripts/build-android.sh passes the workspace version's code
        // (major*10000 + minor*100 + patch, plan 0069) through tauri.conf.
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    buildTypes {
        getByName("debug") {
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {
                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            // No R8 (plan 0056): minification could strip the Kotlin methods
            // Rust calls through JNI, which only a device run would reveal.
            isMinifyEnabled = false
            isDebuggable = false
            isJniDebuggable = false
            proguardFiles(
                *fileTree(".") {
                  include("**/*.pro")
                  exclude("build/**")
                }.files.toTypedArray()
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    buildFeatures {
        buildConfig = true
    }
    lint {
        // lifecycle 2.10.0's LiveData check is built for a newer lint than
        // AGP 8.7.0's and crashes the release build's lintVital pass
        // (IncompatibleClassChangeError). The app uses no LiveData; every
        // other check still runs.
        disable += "NullSafeMutableLiveData"
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_1_8
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = file("tauri.build.gradle.kts"))
