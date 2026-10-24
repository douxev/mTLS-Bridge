plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.douxev.mtls_bridge"
    compileSdk = 36
    // Pin sur le NDK exact de cargo-ndk pour éviter le mismatch strip/objcopy.
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.douxev.mtls_bridge"
        minSdk = 29
        // 36 exigé par Play pour les mises à jour depuis le 31/08/2026.
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            ndk { debugSymbolLevel = "SYMBOL_TABLE" }
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlinOptions { jvmTarget = "21" }
    buildFeatures {
        compose = true
        buildConfig = true
    }

    sourceSets {
        named("main") {
            jniLibs.srcDirs("src/main/jniLibs")
            // Bindings Kotlin générés par uniffi-bindgen.
            java.srcDirs(layout.buildDirectory.dir("generated/uniffi/kotlin"))
        }
    }

    packaging {
        resources {
            excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
        }
    }
}

// ---------------------------------------------------------------------------
// Chaîne Rust → Android : cargo-ndk + uniffi-bindgen en direct, sans plugin.
// ---------------------------------------------------------------------------

val coreDir = layout.projectDirectory.dir("../../core")
val workspaceDir = layout.projectDirectory.dir("../..")
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val uniffiKotlinOutDir = layout.buildDirectory.dir("generated/uniffi/kotlin")

val cargoBuildRust by tasks.registering(Exec::class) {
    group = "rust"
    description = "Build the mtls-bridge-core cdylib pour toutes les ABI Android via cargo-ndk"

    // On repart d'un jniLibs vide : cargo-ndk ne fait qu'ajouter des fichiers,
    // une lib renommée ou retirée (ex. l'ancienne libmtlswrap_core.so) y
    // resterait sinon embarquée dans l'APK.
    doFirst { delete(jniLibsDir) }

    workingDir = workspaceDir.asFile
    commandLine(
        "cargo", "ndk",
        "-t", "arm64-v8a",
        "-t", "armeabi-v7a",
        "-t", "x86_64",
        "--platform", "29",
        "-o", jniLibsDir.asFile.absolutePath,
        "--",
        // --lib : on ne veut PAS recompiler le binaire uniffi-bindgen (askama,
        // cargo_metadata, clap…) pour chaque ABI Android. Le bindgen tourne
        // sur host uniquement, géré par cargoBuildRustHost.
        "build", "--release", "--lib", "-p", "mtls-bridge-core"
    )

    inputs.dir(coreDir.dir("src"))
    inputs.file(coreDir.file("Cargo.toml"))
    inputs.file(workspaceDir.file("Cargo.toml"))
    outputs.dir(jniLibsDir)
}

val cargoBuildRustHost by tasks.registering(Exec::class) {
    group = "rust"
    description = "Build cdylib host pour que uniffi-bindgen lise la métadonnée"

    workingDir = workspaceDir.asFile
    commandLine("cargo", "build", "-p", "mtls-bridge-core")

    inputs.dir(coreDir.dir("src"))
    inputs.file(coreDir.file("Cargo.toml"))
    outputs.file(workspaceDir.file("target/debug/libmtls_bridge_core.so"))
}

val uniffiGenerateBindings by tasks.registering(Exec::class) {
    group = "rust"
    description = "Génère les bindings Kotlin depuis la cdylib mtls-bridge-core"
    dependsOn(cargoBuildRustHost)

    // Repart d'un dossier vide : des bindings d'une ancienne lib (ex.
    // com/douxev/mtlswrap/) seraient sinon toujours compilés dans l'APK.
    doFirst {
        delete(uniffiKotlinOutDir)
        uniffiKotlinOutDir.get().asFile.mkdirs()
    }

    workingDir = workspaceDir.asFile
    commandLine(
        "cargo", "run",
        "-p", "mtls-bridge-core",
        "--bin", "uniffi-bindgen", "--",
        "generate",
        "target/debug/libmtls_bridge_core.so",
        "--language", "kotlin",
        "--no-format",
        "--out-dir", uniffiKotlinOutDir.get().asFile.absolutePath
    )

    inputs.file(workspaceDir.file("target/debug/libmtls_bridge_core.so"))
    inputs.file(coreDir.file("uniffi.toml"))
    outputs.dir(uniffiKotlinOutDir)
}

// Schéma Room exporté (versionné avec le code) : base des migrations futures
// et des tests MigrationTestHelper.
ksp {
    arg("room.schemaLocation", layout.projectDirectory.dir("schemas").asFile.absolutePath)
}

tasks.named("preBuild") {
    dependsOn(cargoBuildRust, uniffiGenerateBindings)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.service)

    // Persistance chiffrée.
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.sqlcipher.android)

    // EncryptedSharedPreferences pour la passphrase DB (clé wrappée par Keystore AES).
    implementation(libs.androidx.security.crypto)

    // BiometricPrompt — utilisé en option pour gater l'utilisation d'une clé Keystore
    // (setUserAuthenticationRequired) ou l'accès à la liste des configs.
    implementation(libs.androidx.biometric)

    // Runtime UniFFI : JNA porte les bindings Kotlin générés.
    implementation(libs.jna) { artifact { type = "aar" } }

    // QR code de l'écran « Configuration à distance ».
    implementation(libs.zxing.core)
}
