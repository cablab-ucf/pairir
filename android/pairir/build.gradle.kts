// Showing and scanning pairir QR codes, in Kotlin; what they carry is
// sealed by the pairir crate (`seal_qr`) in the app's native library.
plugins {
    id("com.android.library") // AGP 9: Kotlin is built in
}

android {
    namespace = "org.pairir"
    compileSdk = 37
    defaultConfig { minSdk = 26 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // ZXing's core: the QR encoder and decoder (pure Java, Apache-2.0, no
    // Play Services). CameraX: Android's own camera library (AOSP).
    implementation("com.google.zxing:core:3.5.4")
    val camerax = "1.6.2"
    implementation("androidx.camera:camera-camera2:$camerax")
    implementation("androidx.camera:camera-lifecycle:$camerax")
    implementation("androidx.camera:camera-view:$camerax")
    implementation("androidx.activity:activity-ktx:1.13.0")
}
