// Showing and scanning irpair QR codes, in Kotlin; what they carry is
// sealed by the irpair crate (`seal_qr`) in the app's native library.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.irpair"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

dependencies {
    // ZXing's core: the QR encoder and decoder (pure Java, Apache-2.0, no
    // Play Services). CameraX: Android's own camera library (AOSP).
    implementation("com.google.zxing:core:3.5.3")
    val camerax = "1.4.1"
    implementation("androidx.camera:camera-camera2:$camerax")
    implementation("androidx.camera:camera-lifecycle:$camerax")
    implementation("androidx.camera:camera-view:$camerax")
    implementation("androidx.activity:activity-ktx:1.9.3")
}
