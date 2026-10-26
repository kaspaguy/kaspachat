# JNI entry points into the Rust core.
-keep class com.kaspaguy.kaspachat.android.core.NativeCore { native <methods>; }
# kotlinx.serialization DTOs used by Retrofit.
-keepattributes *Annotation*, InnerClasses, Signature
-keep,includedescriptorclasses class com.kaspaguy.kaspachat.android.data.remote.**$$serializer { *; }
-keepclassmembers class com.kaspaguy.kaspachat.android.data.remote.** { *** Companion; kotlinx.serialization.KSerializer serializer(...); }
# SQLCipher's JNI.
-keep class net.zetetic.database.** { *; }
# No logging in release builds, whatever slips into the code (security rule: nothing to Logcat).
-assumenosideeffects class android.util.Log { public static *** v(...); public static *** d(...); public static *** i(...); public static *** w(...); public static *** e(...); public static *** wtf(...); }
