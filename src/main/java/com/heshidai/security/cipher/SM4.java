package com.heshidai.security.cipher;

import com.heshidai.security.cipher.internal.Checks;
import com.heshidai.security.cipher.internal.TextCodec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/** SM4 binary operations. Prefer seal/open for new data; ECB/CBC do not authenticate messages. */
public final class SM4 {
    public enum Padding { PKCS7, NONE }
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] MAGIC = {'H', 'S', 'M', '4'};
    private static final int NONCE_LENGTH = 12;
    private SM4() { }

    public static byte[] generateKey() { byte[] key = new byte[16]; RANDOM.nextBytes(key); return key; }
    public static byte[] generateIv() { byte[] iv = new byte[16]; RANDOM.nextBytes(iv); return iv; }

    public static byte[] encryptBlock(byte[] key, byte[] block) { return block(key, block, true); }
    public static byte[] decryptBlock(byte[] key, byte[] block) { return block(key, block, false); }
    private static byte[] block(byte[] key, byte[] input, boolean encrypt) {
        Checks.length(key, 16, "SM4 key"); Checks.length(input, 16, "SM4 block");
        SM4Engine cipher = new SM4Engine(); cipher.init(encrypt, new KeyParameter(key));
        byte[] result = new byte[16]; cipher.processBlock(input, 0, result, 0); return result;
    }

    public static byte[] encryptEcb(byte[] key, byte[] plaintext, Padding padding) {
        try { return crypt(key, null, plaintext, padding, true); }
        catch (CipherException e) { throw new IllegalStateException("SM4 encryption failed", e); }
    }
    public static byte[] decryptEcb(byte[] key, byte[] ciphertext, Padding padding) throws CipherException {
        return crypt(key, null, ciphertext, padding, false);
    }
    public static byte[] encryptCbc(byte[] key, byte[] iv, byte[] plaintext, Padding padding) {
        Checks.length(iv, 16, "SM4 IV");
        try { return crypt(key, iv, plaintext, padding, true); }
        catch (CipherException e) { throw new IllegalStateException("SM4 encryption failed", e); }
    }
    public static byte[] decryptCbc(byte[] key, byte[] iv, byte[] ciphertext, Padding padding) throws CipherException {
        Checks.length(iv, 16, "SM4 IV"); return crypt(key, iv, ciphertext, padding, false);
    }
    private static byte[] crypt(byte[] key, byte[] iv, byte[] input, Padding padding, boolean encrypt) throws CipherException {
        Checks.length(key, 16, "SM4 key"); Checks.required(input, "input"); Checks.required(padding, "padding");
        if ((!encrypt || padding == Padding.NONE) && input.length % 16 != 0) {
            if (!encrypt) throw new CipherException();
            throw new IllegalArgumentException("Unpadded SM4 input must contain complete blocks");
        }
        if (!encrypt && padding == Padding.PKCS7 && input.length == 0) throw new CipherException();
        BlockCipher engine = new SM4Engine();
        CipherParameters params = new KeyParameter(key);
        if (iv != null) {
            engine = CBCBlockCipher.newInstance(engine);
            params = new ParametersWithIV(params, iv.clone());
        }
        DefaultBufferedBlockCipher cipher = padding == Padding.PKCS7
            ? new PaddedBufferedBlockCipher(engine) : new DefaultBufferedBlockCipher(engine);
        cipher.init(encrypt, params);
        byte[] result = new byte[cipher.getOutputSize(input.length)];
        try {
            int size = cipher.processBytes(input, 0, input.length, result, 0);
            size += cipher.doFinal(result, size);
            return Arrays.copyOf(result, size);
        } catch (InvalidCipherTextException | RuntimeException e) {
            Arrays.fill(result, (byte) 0); throw new CipherException(e);
        }
    }

    /** Advanced API: caller must ensure this 12-byte nonce is never reused under the same key. */
    public static byte[] encryptGcm(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        try { return gcm(key, nonce, plaintext, aad, true); }
        catch (CipherException e) { throw new IllegalStateException("SM4 encryption failed", e); }
    }
    public static byte[] decryptGcm(byte[] key, byte[] nonce, byte[] ciphertextAndTag, byte[] aad) throws CipherException {
        return gcm(key, nonce, ciphertextAndTag, aad, false);
    }
    private static byte[] gcm(byte[] key, byte[] nonce, byte[] input, byte[] aad, boolean encrypt) throws CipherException {
        Checks.length(key, 16, "SM4 key"); Checks.length(nonce, NONCE_LENGTH, "GCM nonce");
        Checks.required(input, "input"); Checks.required(aad, "AAD");
        if (!encrypt && input.length < 16) throw new CipherException();
        GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
        cipher.init(encrypt, new AEADParameters(new KeyParameter(key), 128, nonce.clone(), aad.clone()));
        byte[] result = new byte[cipher.getOutputSize(input.length)];
        try {
            int size = cipher.processBytes(input, 0, input.length, result, 0);
            size += cipher.doFinal(result, size);
            return Arrays.copyOf(result, size);
        } catch (InvalidCipherTextException | RuntimeException e) {
            Arrays.fill(result, (byte) 0); throw new CipherException(e);
        }
    }

    /** Versioned local envelope, with an authenticated key ID and a fresh random 96-bit nonce. */
    public static byte[] seal(byte[] key, String keyId, byte[] plaintext, byte[] aad) {
        Checks.length(key, 16, "SM4 key"); Checks.required(plaintext, "plaintext"); Checks.required(aad, "AAD");
        byte[] id = TextCodec.encode(Checks.required(keyId, "key ID"), StandardCharsets.UTF_8);
        if (id.length < 1 || id.length > 255) throw new IllegalArgumentException("Key ID must contain 1 to 255 UTF-8 bytes");
        byte[] header = new byte[8 + id.length];
        System.arraycopy(MAGIC, 0, header, 0, 4);
        header[4] = 1; header[5] = 1; header[6] = 0; header[7] = (byte) id.length;
        System.arraycopy(id, 0, header, 8, id.length);
        byte[] nonce = new byte[NONCE_LENGTH]; RANDOM.nextBytes(nonce);
        byte[] encrypted = encryptGcm(key, nonce, plaintext, envelopeAad(header, aad));
        byte[] envelope = new byte[Math.addExact(header.length + NONCE_LENGTH, encrypted.length)];
        System.arraycopy(header, 0, envelope, 0, header.length);
        System.arraycopy(nonce, 0, envelope, header.length, NONCE_LENGTH);
        System.arraycopy(encrypted, 0, envelope, header.length + NONCE_LENGTH, encrypted.length);
        return envelope;
    }

    public static byte[] open(byte[] key, byte[] envelope, byte[] aad) throws CipherException {
        Checks.length(key, 16, "SM4 key"); Checks.required(aad, "AAD");
        int headerLength = headerLength(envelope);
        byte[] header = Arrays.copyOf(envelope, headerLength);
        return decryptGcm(key, Arrays.copyOfRange(envelope, headerLength, headerLength + NONCE_LENGTH),
            Arrays.copyOfRange(envelope, headerLength + NONCE_LENGTH, envelope.length), envelopeAad(header, aad));
    }

    /** Unauthenticated routing hint only. Trust this ID only after open has authenticated the envelope. */
    public static String envelopeKeyId(byte[] envelope) throws CipherException {
        int length = headerLength(envelope);
        return TextCodec.decode(Arrays.copyOfRange(envelope, 8, length), StandardCharsets.UTF_8);
    }

    private static int headerLength(byte[] envelope) throws CipherException {
        Checks.required(envelope, "envelope");
        if (envelope.length < 37 || !Arrays.equals(MAGIC, Arrays.copyOf(envelope, 4))
            || envelope[4] != 1 || envelope[5] != 1 || envelope[6] != 0) throw new CipherException();
        int idLength = envelope[7] & 255;
        int headerLength = 8 + idLength;
        if (idLength == 0 || envelope.length < headerLength + NONCE_LENGTH + 16) throw new CipherException();
        try { TextCodec.decode(Arrays.copyOfRange(envelope, 8, headerLength), StandardCharsets.UTF_8); }
        catch (IllegalArgumentException e) { throw new CipherException(e); }
        return headerLength;
    }

    private static byte[] envelopeAad(byte[] header, byte[] external) {
        byte[] aad = new byte[Math.addExact(header.length, external.length)];
        System.arraycopy(header, 0, aad, 0, header.length);
        System.arraycopy(external, 0, aad, header.length, external.length);
        return aad;
    }
}
