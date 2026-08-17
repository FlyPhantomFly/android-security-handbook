-keep class com.pentest.ch42.vault.VaultEntryPoint {
    public static void main(java.lang.String[]);
}
-keepattributes RuntimeVisibleAnnotations
-keepattributes AnnotationDefault
-keep class kotlin.Metadata { *; }
# The pattern real apps ship: a whole model package kept for reflection/JSON,
# but with allowobfuscation so R8 still renames it.
-keep,allowobfuscation class com.pentest.ch42.vault.** { *; }
-dontwarn kotlin.**
-dontwarn org.jetbrains.annotations.**
-dontwarn java.lang.invoke.**
