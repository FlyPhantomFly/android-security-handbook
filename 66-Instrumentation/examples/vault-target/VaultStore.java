// examples/vault-target/VaultStore.java
//
// The target's private state, in the three shapes an instrumentation can reach:
//
//   * a private static field                  (sSessionToken)
//   * a SharedPreferences XML file            (shared_prefs/vault.xml)
//   * an ordinary file in the private data dir (files/secret.txt)
//
// None of these is a vulnerability. All three are correct, ordinary Android
// storage, mode 0600 under /data/data/com.pentest.ch66.vault. The chapter's
// claim is that `am instrument` reads all three without root and without Frida,
// because the code doing the reading is running as this app's own UID.
//
// AUTHORISED TESTING ONLY. The values below are fixtures, not real credentials.

package com.pentest.ch66.vault;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class VaultStore {

    /** Private static state. Survives for the life of the process. */
    private static String sSessionToken = "not-issued";

    /**
     * An interface-typed collaborator in a static field. This is the shape that
     * java.lang.reflect.Proxy can intercept without any native code, and
     * examples/HookFromInstrumentation.java does exactly that -- see chapter 66
     * section 9.4. Nothing about this field is unusual; it is how a large
     * fraction of real Android code wires up analytics and networking.
     */
    static Telemetry sSink = new Telemetry() {
        @Override
        public void event(String name, String value) {
            android.util.Log.i("ch66sink", "event " + name + "=" + value);
        }
    };

    private VaultStore() {
    }

    /** The app's own call site. Deliberately goes through the static field. */
    public static void emit(String name, String value) {
        sSink.event(name, value);
    }

    /** Populate every storage channel the probe will later go looking for. */
    public static void seed(Context ctx) {
        sSessionToken = "sess-" + Long.toHexString(0xC66L * 0x9E3779B9L);

        SharedPreferences prefs = ctx.getSharedPreferences("vault", Context.MODE_PRIVATE);
        prefs.edit()
                .putString("api_key", "ch66-APIKEY-3f9a1c")
                .putString("refresh_token", "ch66-RT-8b20e5d4")
                .putBoolean("premium", false)
                .commit();

        File f = new File(ctx.getFilesDir(), "secret.txt");
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write("ch66-file-secret-7d41\n".getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // A fixture that fails to write is a fixture that fails loudly in
            // the lab, which is the behaviour we want.
        }
    }

    public static String currentSessionToken() {
        return sSessionToken;
    }
}
