package com.heshidai.security.cipher.legacy;

import com.heshidai.security.cipher.CipherException;
import com.heshidai.security.cipher.internal.Sm2Core;

/**
 * Read-only migration of the original 8542D69E test-curve DER format.
 * Historical signature verification does not restore secrecy of compromised old signing keys.
 * There is deliberately no key generation, encryption or signing API on this curve.
 */
public final class LegacySM2 {
    private LegacySM2() { }

    public static byte[] decrypt(byte[] unsignedPrivateKey, byte[] derCiphertext) throws CipherException {
        return Sm2Core.decryptLegacy(unsignedPrivateKey, derCiphertext);
    }

    public static boolean verifySignature(byte[] userId, byte[] publicKey, byte[] message, byte[] derSignature) {
        return Sm2Core.verifyLegacy(userId, publicKey, message, derSignature);
    }
}
