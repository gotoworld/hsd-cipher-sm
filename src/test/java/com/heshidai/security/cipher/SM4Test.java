package com.heshidai.security.cipher;

import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static com.heshidai.security.cipher.Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class SM4Test {
    private static final byte[] KEY = Hex.decode("0123456789abcdeffedcba9876543210");
    @Test void standardBlockAndMillionIterationVectors() {
        byte[] result = SM4.encryptBlock(KEY, KEY);
        assertEquals("681edf34d206965e86b3e94f536e4246", Hex.encode(result));
        assertArrayEquals(KEY, SM4.decryptBlock(KEY, result));
        // GB/T SM4 million-iteration vector; reuse a BC engine, rather than 1M API allocations.
        org.bouncycastle.crypto.engines.SM4Engine engine = new org.bouncycastle.crypto.engines.SM4Engine();
        engine.init(true, new org.bouncycastle.crypto.params.KeyParameter(KEY));
        byte[] block = KEY.clone();
        for (int i = 0; i < 1000000; i++) engine.processBlock(block, 0, block, 0);
        assertEquals("595298c7c6fd271f0402f804c33d3f66", Hex.encode(block));
    }

    @ParameterizedTest @ValueSource(ints = {0, 1, 15, 16, 17, 31, 32, 65, 1024})
    void modesRoundTripWithoutMutatingInputs(int size) throws Exception {
        byte[] input = new byte[size]; new Random(size).nextBytes(input); byte[] snapshot = input.clone();
        byte[] iv = SM4.generateIv(), before = iv.clone(), keyBefore = KEY.clone();
        byte[] ct = SM4.encryptCbc(KEY, iv, input, SM4.Padding.PKCS7);
        assertArrayEquals(input, SM4.decryptCbc(KEY, iv, ct, SM4.Padding.PKCS7));
        assertArrayEquals(input, SM4.decryptEcb(KEY, SM4.encryptEcb(KEY, input, SM4.Padding.PKCS7), SM4.Padding.PKCS7));
        assertArrayEquals(before, iv); assertArrayEquals(snapshot, input); assertArrayEquals(keyBefore, KEY);
        byte[] envelope = SM4.seal(KEY, "key-2026", input, utf8("context"));
        assertArrayEquals(input, SM4.open(KEY, envelope, utf8("context")));
        assertEquals("key-2026", SM4.envelopeKeyId(envelope));
    }

    @Test void strictPaddingAndBlockLengthChecks() throws Exception {
        for (int pad : new int[] {0, 2, 3, 15, 16, 17, 255}) {
            byte[] block = new byte[16]; Arrays.fill(block, (byte) 0x41); block[15] = (byte) pad;
            byte[] invalid = SM4.encryptEcb(KEY, block, SM4.Padding.NONE);
            assertThrows(CipherException.class, () -> SM4.decryptEcb(KEY, invalid, SM4.Padding.PKCS7));
            byte[] iv = new byte[16], invalidCbc = SM4.encryptCbc(KEY, iv, block, SM4.Padding.NONE);
            assertThrows(CipherException.class, () -> SM4.decryptCbc(KEY, iv, invalidCbc, SM4.Padding.PKCS7));
        }
        for (int length : new int[] {0, 1, 15, 17}) {
            assertThrows(CipherException.class, () -> SM4.decryptEcb(KEY, new byte[length], SM4.Padding.PKCS7));
            assertThrows(CipherException.class, () -> SM4.decryptCbc(KEY, new byte[16], new byte[length], SM4.Padding.PKCS7));
        }
        assertThrows(CipherException.class, () -> SM4.decryptEcb(KEY, new byte[15], SM4.Padding.NONE));
        assertThrows(IllegalArgumentException.class, () -> SM4.encryptEcb(KEY, new byte[15], SM4.Padding.NONE));
        assertArrayEquals(new byte[0], SM4.decryptEcb(KEY, new byte[0], SM4.Padding.NONE));
        assertThrows(IllegalArgumentException.class, () -> SM4.encryptCbc(KEY, null, new byte[0], SM4.Padding.PKCS7));
        assertThrows(IllegalArgumentException.class, () -> SM4.encryptBlock(new byte[15], new byte[16]));
    }

    @Test void rfc8998GcmVectorAuthenticatesCiphertextNonceAndAad() throws Exception {
        // https://www.rfc-editor.org/rfc/rfc8998.html#appendix-A.1
        byte[] nonce = Hex.decode("00001234567800000000ABCD"), aad = Hex.decode("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
        byte[] message = Hex.decode("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
            + "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");
        byte[] expected = Hex.decode("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735"
            + "D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D83DE3541E4C2B58177E065A9BF7B62EC");
        assertArrayEquals(expected, SM4.encryptGcm(KEY, nonce, message, aad));
        assertArrayEquals(message, SM4.decryptGcm(KEY, nonce, expected, aad));
        for (int i : new int[] {0, expected.length - 1}) {
            assertThrows(CipherException.class, () -> SM4.decryptGcm(KEY, nonce, change(expected, i), aad));
        }
        assertThrows(CipherException.class, () -> SM4.decryptGcm(KEY, change(nonce, 0), expected, aad));
        assertThrows(CipherException.class, () -> SM4.decryptGcm(KEY, nonce, expected, change(aad, 0)));
        assertThrows(CipherException.class, () -> SM4.decryptGcm(SM4.generateKey(), nonce, expected, aad));
        assertThrows(CipherException.class, () -> SM4.decryptGcm(KEY, nonce, new byte[15], aad));
    }

    @Test void envelopeAuthenticatesAllMetadataAndGeneratesFreshNonces() throws Exception {
        byte[] aad = utf8("record ID"), message = utf8("payload");
        byte[] envelope = SM4.seal(KEY, "密钥1", message, aad);
        assertEquals("密钥1", SM4.envelopeKeyId(envelope));
        assertArrayEquals(message, SM4.open(KEY, envelope, aad));
        assertFalse(Arrays.equals(envelope, SM4.seal(KEY, "密钥1", message, aad)));
        for (int i = 0; i < envelope.length; i++) {
            final int at = i;
            assertThrows(CipherException.class, () -> SM4.open(KEY, change(envelope, at), aad));
        }
        assertThrows(CipherException.class, () -> SM4.open(KEY, envelope, change(aad, 0)));
        assertThrows(CipherException.class, () -> SM4.open(KEY, Arrays.copyOf(envelope, envelope.length - 1), aad));
        assertThrows(CipherException.class, () -> SM4.open(KEY, Arrays.copyOf(envelope, 10), aad));
        assertThrows(IllegalArgumentException.class, () -> SM4.seal(KEY, "", message, aad));
        assertThrows(IllegalArgumentException.class, () -> SM4.seal(KEY, new String(new char[256]).replace('\0', 'a'), message, aad));
    }

    @Test void utf8WrapperAndExplicitGbkMigrationPreserveText() {
        SM4Utils wrapper = new SM4Utils(); wrapper.setSecretKey("0123456789abcdef"); wrapper.setIv("fedcba9876543210");
        String text = "你好🙂\u0000";
        assertEquals(text, wrapper.decryptData_ECB(wrapper.encryptData_ECB(text)));
        assertEquals(text, wrapper.decryptData_CBC(wrapper.encryptData_CBC(text)));
        wrapper.setCharset(Charset.forName("GBK"));
        assertEquals(legacy("sm4.message.utf8"), wrapper.decryptData_ECB(legacy("sm4.ecb.base64")));
        assertEquals(legacy("sm4.message.utf8"), wrapper.decryptData_CBC(legacy("sm4.cbc.base64")));
        assertEquals(legacy("sm4.cbc.base64"), wrapper.encryptData_CBC(legacy("sm4.message.utf8")));
        assertThrows(IllegalArgumentException.class, () -> wrapper.encryptData_ECB("🙂"));
        assertThrows(IllegalArgumentException.class, () -> wrapper.decryptData_ECB("invalid!"));
        wrapper.setHexString(true); wrapper.setSecretKey("GG");
        assertThrows(IllegalArgumentException.class, () -> wrapper.encryptData_ECB("message"));
    }
}
