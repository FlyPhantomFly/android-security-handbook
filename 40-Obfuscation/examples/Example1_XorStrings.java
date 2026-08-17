// examples/Example1_XorStrings.java
package com.example.obf;

public final class Strings {
    private static final byte KEY = 0x5A;

    // Ciphertext for "https://api.example.com/v1/login"
    private static final byte[] S0 = {
        0x32, 0x2e, 0x2e, 0x3e, 0x39, 0x75, 0x75, 0x3b, 0x2a, 0x33,
        0x74, 0x3f, 0x38, 0x3b, 0x37, 0x2a, 0x36, 0x3f, 0x74, 0x39,
        0x35, 0x37, 0x75, 0x2c, 0x6b, 0x75, 0x36, 0x35, 0x39, 0x33, 0x34
    };

    public static String get(int id) {
        byte[] src = (id == 0) ? S0 : null;
        if (src == null) return null;
        byte[] out = new byte[src.length];
        for (int i = 0; i < src.length; i++) out[i] = (byte) (src[i] ^ KEY);
        return new String(out, java.nio.charset.StandardCharsets.UTF_8);
    }
}
