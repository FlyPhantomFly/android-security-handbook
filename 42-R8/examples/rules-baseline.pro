# Baseline: keep only the entry point, exactly as an app keeps only its
# manifest-declared components. Everything else is fair game for R8.
-keep class com.pentest.ch42.vault.VaultEntryPoint {
    public static void main(java.lang.String[]);
}

-dontwarn kotlin.**
-dontwarn org.jetbrains.annotations.**
-dontwarn java.lang.invoke.**
