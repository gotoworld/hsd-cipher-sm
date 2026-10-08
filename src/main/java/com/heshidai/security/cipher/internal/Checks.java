package com.heshidai.security.cipher.internal;

/** Internal validation helpers; not a supported public API. */
public final class Checks {
    private Checks() { }

    public static <T> T required(T value, String name) {
        if (value == null) throw new IllegalArgumentException(name + " must not be null");
        return value;
    }

    public static byte[] length(byte[] value, int length, String name) {
        required(value, name);
        if (value.length != length) throw new IllegalArgumentException(name + " must contain " + length + " bytes");
        return value;
    }

    public static void range(byte[] value, int offset, int length) {
        required(value, "buffer");
        if (offset < 0 || length < 0 || offset > value.length - length) {
            throw new IllegalArgumentException("Invalid buffer offset or length");
        }
    }
}
