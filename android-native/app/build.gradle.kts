import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

// Server endpoints and the private-testnet basic auth come from local.properties (never committed):
//   kaspachat.apiOrigin=https://testnet.kaspachat.com
//   kaspachat.apiAuth=<base64 of user:password>   (testnet only)
val local = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun localProp(key: String, default: String) = (local.getProperty(key) ?: default).replace("\"", "")

val coreDir = rootProject.file("core")
val cargo = File(System.getProperty("user.home"), ".cargo/bin/cargo").takeIf { it.exists() }?.path ?: "cargo"

android {
    namespace = "com.kaspaguy.kaspachat.android"
    compileSdk = 37
    ndkVersion = "30.0.16248370"

    defaultConfig {
        applicationId = "com.kaspaguy.kaspachat.android"
        minSdk = 28
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "API_ORIGIN", "\"${localProp("kaspachat.apiOrigin", "https://testnet.kaspachat.com")}\"")
        buildConfigField("String", "API_AUTH", "\"${localProp("kaspachat.apiAuth", "")}\"")
        // Play/App Store builds sell nothing in the app (Play billing policy, as in app/src/lib/platform.ts storeBuild).
        buildConfigField("boolean", "STORE_BUILD", localProp("kaspachat.storeBuild", "false"))
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}

ksp {
    arg("room.generateKotlin", "true")
}

// The Rust core (core/, wrapping rust-impl): cross-compiled for the device ABIs before every build, and for the
// host so JVM unit tests exercise the real JNI bridge. Skip with -PskipRust once the libraries are built.
val buildRustAndroid by tasks.registering(Exec::class) {
    onlyIf { !project.hasProperty("skipRust") }
    workingDir = coreDir
    val ndkDir = androidComponents.sdkComponents.ndkDirectory
    doFirst { environment("ANDROID_NDK_HOME", ndkDir.get().asFile.path) }
    commandLine(cargo, "ndk", "-t", "arm64-v8a", "-t", "x86_64", "--platform", "28", "-o", file("src/main/jniLibs").path, "build", "--release")
}
val buildRustHost by tasks.registering(Exec::class) {
    onlyIf { !project.hasProperty("skipRust") }
    workingDir = coreDir
    commandLine(cargo, "build", "--release")
}
tasks.named("preBuild") { dependsOn(buildRustAndroid) }
tasks.withType<Test>().configureEach {
    dependsOn(buildRustHost)
    systemProperty("java.library.path", File(coreDir, "target/release").path)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    debugImplementation(libs.compose.ui.tooling)

    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)
    implementation(libs.sqlcipher)
    implementation(libs.androidx.sqlite)
    implementation(libs.work.runtime)

    implementation(platform(libs.koin.bom))
    implementation(libs.koin.android)
    implementation(libs.koin.compose.viewmodel)

    implementation(libs.retrofit)
    implementation(libs.retrofit.serialization)
    implementation(libs.okhttp)
    implementation(libs.serialization.json)
    implementation(libs.coroutines.android)
    implementation(libs.zxing.core)

    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
