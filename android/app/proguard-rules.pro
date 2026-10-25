# Keep the JNA and uniffi bindings (runtime reflection and native lookups).
# JNA's classes live in com.sun.jna (net.java.dev.jna is only its Maven group).
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { public *; }
-dontwarn java.awt.**
-keep class com.douxev.mtls_bridge.ffi.** { *; }
-keepclassmembers class * extends com.sun.jna.Structure {
    <fields>;
}

# Tink (pulled in by androidx.security:security-crypto) references
# compile-time-only annotations that are not shipped at runtime.
-dontwarn com.google.errorprone.annotations.**
-dontwarn javax.annotation.**
