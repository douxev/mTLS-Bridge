# Garde les bindings JNA et uniffi (réflexion à l'exécution).
-keep class net.java.dev.jna.** { *; }
-keep class com.douxev.mtls_bridge.ffi.** { *; }
-keepclassmembers class * extends com.sun.jna.Structure {
    <fields>;
}
