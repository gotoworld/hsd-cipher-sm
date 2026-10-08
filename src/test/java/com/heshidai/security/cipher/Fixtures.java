package com.heshidai.security.cipher;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

final class Fixtures {
    private static final Properties LEGACY = new Properties();
    static {
        try (InputStream input = Fixtures.class.getResourceAsStream("/legacy-v1.properties")) {
            if (input == null) throw new IOException("Missing legacy fixture");
            LEGACY.load(input);
        } catch (IOException e) { throw new ExceptionInInitializerError(e); }
    }
    static byte[] utf8(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    static byte[] legacyHex(String key) { return Hex.decode(LEGACY.getProperty(key)); }
    static String legacy(String key) { return LEGACY.getProperty(key); }
    static byte[] change(byte[] input, int position) { byte[] changed = input.clone(); changed[position] ^= 1; return changed; }
}
