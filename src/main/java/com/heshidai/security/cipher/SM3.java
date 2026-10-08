package com.heshidai.security.cipher;

import com.heshidai.security.cipher.internal.Checks;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/** SM3 digests and HMAC-SM3. These stateless methods do not close caller-owned streams. */
public final class SM3 {
    private SM3() { }
    public static byte[] digest(byte[] input) {
        Checks.required(input, "input");
        SM3Digest digest = new SM3Digest(); digest.update(input, 0, input.length);
        byte[] output = new byte[32]; digest.doFinal(output, 0); return output;
    }
    public static byte[] digest(InputStream input) throws IOException {
        Checks.required(input, "input");
        SM3Digest digest = new SM3Digest(); byte[] buffer = new byte[8192]; int read;
        while ((read = input.read(buffer)) != -1) {
            if (read == 0) {
                int single = input.read();
                if (single == -1) break;
                digest.update((byte) single);
            } else digest.update(buffer, 0, read);
        }
        byte[] output = new byte[32]; digest.doFinal(output, 0); return output;
    }
    public static byte[] hmac(byte[] key, byte[] message) {
        Checks.required(key, "HMAC key"); Checks.required(message, "message");
        if (key.length == 0) throw new IllegalArgumentException("HMAC key must not be empty");
        HMac mac = new HMac(new org.bouncycastle.crypto.digests.SM3Digest());
        mac.init(new KeyParameter(key)); mac.update(message, 0, message.length);
        byte[] output = new byte[mac.getMacSize()]; mac.doFinal(output, 0); return output;
    }
    public static boolean verifyHmac(byte[] key, byte[] message, byte[] expected) {
        Checks.required(expected, "expected MAC");
        return org.bouncycastle.util.Arrays.constantTimeAreEqual(hmac(key, message), expected);
    }
}
