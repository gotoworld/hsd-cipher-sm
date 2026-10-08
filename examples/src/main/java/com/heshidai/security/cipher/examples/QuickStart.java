package com.heshidai.security.cipher.examples;

import com.heshidai.security.cipher.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Standalone consumer of the packaged public API; all keys are ephemeral example keys. */
public final class QuickStart {
    private QuickStart() { }
    public static void main(String[] args) throws Exception {
        byte[] message = "Hello 国密🙂".getBytes(StandardCharsets.UTF_8);
        SM2KeyPair keys = SM2Utils.generateKeyPair();
        byte[] encrypted = SM2Utils.encrypt(keys.getPublicKey(), message, SM2CiphertextFormat.DER);
        require(Arrays.equals(message, SM2Utils.decrypt(keys.getPrivateKey(), encrypted)), "SM2 roundtrip");
        byte[] userId = SM2Utils.defaultUserId();
        byte[] signature = SM2Utils.sign(userId, keys.getPrivateKey(), message);
        require(SM2Utils.verifySign(userId, keys.getPublicKey(), message, signature), "SM2 signature");
        require(Arrays.equals(keys.getPrivateKey(), SM2Utils.privateKeyFromPem(SM2Utils.privateKeyToPem(keys.getPrivateKey()))), "PKCS8 PEM");
        require(SM3.digest(message).length == 32, "SM3 digest");
        byte[] macKey = new byte[32]; new java.security.SecureRandom().nextBytes(macKey);
        require(SM3.verifyHmac(macKey, message, SM3.hmac(macKey, message)), "HMAC-SM3");
        byte[] dataKey = SM4.generateKey(), aad = "example record ID".getBytes(StandardCharsets.UTF_8);
        byte[] sealed = SM4.seal(dataKey, "example-key-1", message, aad);
        require(Arrays.equals(message, SM4.open(dataKey, sealed, aad)), "SM4 authenticated envelope");
        System.out.println("SM2, key files, SM3, HMAC-SM3 and SM4-GCM examples passed.");
    }
    private static void require(boolean condition, String operation) {
        if (!condition) throw new IllegalStateException(operation + " failed");
    }
}
