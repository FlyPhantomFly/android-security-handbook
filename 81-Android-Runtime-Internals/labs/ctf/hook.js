/*
 * hook.js — Lab 04 answer key. Do not read this before forming a hypothesis.
 *
 * WHAT IT DOES
 *   Hooks com.artlab.vault.Vault.check(String) and forces it to return false,
 *   while logging each call. The target's DEX is not modified.
 *
 * HOW TO RUN
 *   adb shell "CLASSPATH=/data/local/tmp/vault.dex app_process /system/bin com.artlab.vault.Vault" &
 *   frida -U -p <pid> -l 81-Android-Runtime-Internals/labs/ctf/hook.js
 */

Java.perform(function () {
    var Vault = Java.use("com.artlab.vault.Vault");

    Vault.check.overload("java.lang.String").implementation = function (candidate) {
        console.log("[hook] check(" + candidate + ") -> false");
        return false;
    };

    console.log("[hook] installed on Vault.check(String)");
});
