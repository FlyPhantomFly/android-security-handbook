// examples/Example3_DynamicLoader.java
package com.example.obf;

import android.content.Context;
import dalvik.system.InMemoryDexClassLoader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Bootstrap {

    private static final byte[] KEY = {
        (byte)0x8f,0x2a,0x11,0x00,0x5c,0x3d,(byte)0x9e,0x74,
        0x21,0x66,(byte)0xab,0x03,0x5f,(byte)0xc1,0x1d,0x42
    };
    private static final byte[] IV = new byte[16];

    /** Called from a stub Application.attachBaseContext(). */
    public static void boot(Context ctx) throws Exception {
        byte[] blob = readAsset(ctx, "cfg/payload.dat");
        byte[] dex  = decrypt(blob);
        ClassLoader cl = new InMemoryDexClassLoader(ByteBuffer.wrap(dex), ctx.getClassLoader());
        Class<?> core = cl.loadClass("com.example.real.Core");
        core.getMethod("start", Context.class).invoke(null, ctx);
    }

    private static byte[] decrypt(byte[] in) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"), new IvParameterSpec(IV));
        return c.doFinal(in);
    }

    private static byte[] readAsset(Context ctx, String name) throws Exception {
        InputStream is = ctx.getAssets().open(name);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        is.close();
        return bos.toByteArray();
    }
}
