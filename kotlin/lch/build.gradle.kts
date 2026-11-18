// 実行時の外部部品は入れない（規格書 第7章）。試験の部品（JUnit）だけを使う
plugins {
    id("com.android.library")
}

android {
    namespace = "jp.loverhetoric.lch"
    compileSdk = 36
    defaultConfig {
        // 承認の鍵の生体認証（AUTH_BIOMETRIC_STRONG）と BiometricPrompt の認証の種類の指定は Android 11 から
        minSdk = 30
        // 端末の上の試験（src/androidTest。模擬端末でも動く）
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    testOptions {
        unitTests.all { test ->
            // 相互の確認（swift/Interop/server.ts の受け口）の場所を、試験に渡す
            listOf("LCH_INTEROP_URL", "LCH_INTEROP_TOKEN", "LCH_INTEROP_CODE").forEach { k -> System.getenv(k)?.let { test.environment(k, it) } }
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    // 端末の上の試験の部品（試験だけ。アプリには入らない）
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
