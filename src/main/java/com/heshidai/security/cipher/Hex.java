package com.heshidai.security.cipher;

import com.heshidai.security.cipher.internal.Checks;

/** Strict ASCII hexadecimal encoding. Empty input is valid; whitespace and odd lengths are not. */
public final class Hex {
    private static final char[] DIGITS = "0123456789abcdef".toCharArray();
    private Hex() { }

    public static String encode(byte[] input) {
        Checks.required(input, "input");
        char[] out = new char[Math.multiplyExact(input.length, 2)];
        for (int i = 0; i < input.length; i++) {
            out[i * 2] = DIGITS[(input[i] & 255) >>> 4];
            out[i * 2 + 1] = DIGITS[input[i] & 15];
        }
        return new String(out);
    }

    public static byte[] decode(String input) {
        Checks.required(input, "input");
        if ((input.length() & 1) != 0) throw new IllegalArgumentException("Hex length must be even");
        byte[] out = new byte[input.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((digit(input.charAt(i * 2)) << 4) | digit(input.charAt(i * 2 + 1)));
        }
        return out;
    }

    public static int digit(char ch) {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        throw new IllegalArgumentException("Invalid hexadecimal digit");
    }
}
