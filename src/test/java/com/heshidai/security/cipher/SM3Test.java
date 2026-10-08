package com.heshidai.security.cipher;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static com.heshidai.security.cipher.Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class SM3Test {
    @Test void standardVectors() {
        assertEquals("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", Hex.encode(SM3.digest(utf8("abc"))));
        StringBuilder data = new StringBuilder(); for (int i = 0; i < 16; i++) data.append("abcd");
        assertEquals("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", Hex.encode(SM3.digest(utf8(data.toString()))));
        assertEquals("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", Hex.encode(SM3.digest(new byte[0])));
    }

    @ParameterizedTest @ValueSource(ints = {0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 65536})
    void arbitraryChunksOffsetsCopyAndReuseMatch(int length) throws Exception {
        byte[] input = new byte[length]; new Random(length).nextBytes(input);
        byte[] expected = SM3.digest(input);
        for (int chunk : new int[] {1, 3, 63, 64, 65, 1024}) {
            SM3Digest digest = new SM3Digest();
            for (int at = 0; at < length; at += chunk) digest.update(input, at, Math.min(chunk, length - at));
            SM3Digest copy = new SM3Digest(digest);
            byte[] offset = new byte[48]; Arrays.fill(offset, (byte) 0x55); digest.doFinal(offset, 8);
            assertArrayEquals(expected, Arrays.copyOfRange(offset, 8, 40));
            for (int i : new int[] {0, 7, 40, 47}) assertEquals((byte) 0x55, offset[i]);
            byte[] copied = new byte[32]; copy.doFinal(copied, 0); assertArrayEquals(expected, copied);
            digest.update(input, 0, input.length); byte[] reused = new byte[32]; digest.doFinal(reused, 0);
            assertArrayEquals(expected, reused);
        }
        assertArrayEquals(expected, SM3.digest(new ByteArrayInputStream(input)));
    }

    @Test void invalidBuffersDoNotConsumeDigestState() {
        SM3Digest digest = new SM3Digest(); digest.update(utf8("abc"), 0, 3);
        assertThrows(IllegalArgumentException.class, () -> digest.doFinal(new byte[32], 1));
        assertThrows(IllegalArgumentException.class, () -> digest.update(new byte[2], Integer.MAX_VALUE, 1));
        assertThrows(IllegalArgumentException.class, () -> digest.update(new byte[2], 0, -1));
        byte[] out = new byte[32]; digest.doFinal(out, 0); assertArrayEquals(SM3.digest(utf8("abc")), out);
        digest.update((byte) 1); digest.reset(); digest.doFinal(out, 0); assertArrayEquals(SM3.digest(new byte[0]), out);
    }

    @Test void streamAboveOld256MiBBoundaryHasCorrectDigestWithoutLargeAllocation() throws Exception {
        // Independently generated using: 256 MiB + 1 zero bytes | openssl dgst -sm3.
        InputStream zeros = new InputStream() {
            private long remaining = 256L * 1024 * 1024 + 1;
            @Override public int read() { if (remaining == 0) return -1; remaining--; return 0; }
            @Override public int read(byte[] b, int off, int len) {
                if (remaining == 0) return -1;
                int count = (int) Math.min(remaining, len); Arrays.fill(b, off, off + count, (byte) 0);
                remaining -= count; return count;
            }
        };
        assertEquals("075ff40f666aa43f2dd5ee1289c4c2f3451209bc4d585c988a245cde4595991b", Hex.encode(SM3.digest(zeros)));
    }

    @Test void streamIsNotClosedAndZeroReadsMakeProgress() throws Exception {
        boolean[] closed = {false};
        InputStream input = new ByteArrayInputStream(utf8("abc")) {
            private boolean once;
            @Override public synchronized int read(byte[] b, int off, int len) { if (!once) { once = true; return 0; } return super.read(b, off, len); }
            @Override public void close() { closed[0] = true; }
        };
        assertArrayEquals(SM3.digest(utf8("abc")), SM3.digest(input)); assertFalse(closed[0]);
    }

    @Test void hmacMatchesJcaAndChecksAuthentication() throws Exception {
        byte[] key = utf8("a dedicated non-production authentication key"), message = utf8("authenticated message");
        Mac reference = Mac.getInstance("HMACSM3", new BouncyCastleProvider());
        reference.init(new SecretKeySpec(key, "HMACSM3"));
        assertArrayEquals(reference.doFinal(message), SM3.hmac(key, message));
        byte[] expected = SM3.hmac(key, message);
        assertTrue(SM3.verifyHmac(key, message, expected));
        assertFalse(SM3.verifyHmac(key, change(message, 0), expected));
        assertFalse(SM3.verifyHmac(key, message, Arrays.copyOf(expected, 31)));
        assertThrows(IllegalArgumentException.class, () -> SM3.hmac(new byte[0], message));
    }
}
