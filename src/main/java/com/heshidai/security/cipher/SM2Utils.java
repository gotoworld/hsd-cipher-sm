package com.heshidai.security.cipher;

import com.heshidai.security.cipher.internal.Sm2Core;
import com.heshidai.security.cipher.internal.Pem;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Standard sm2p256v1 operations. Raw private keys contain exactly 32 unsigned bytes. */
public final class SM2Utils {
    private SM2Utils() { }

    /** Returns a copy of the common ID; explicit IDs must match the peer's protocol. */
    public static byte[] defaultUserId() { return "1234567812345678".getBytes(StandardCharsets.US_ASCII); }

    public static SM2KeyPair generateKeyPair() {
        byte[] key = Sm2Core.generatePrivateKey();
        return new SM2KeyPair(key, Sm2Core.derivePublicKey(key));
    }

    public static byte[] publicKeyFromPrivateKey(byte[] key) { return Sm2Core.derivePublicKey(key); }
    public static byte[] compressPublicKey(byte[] key) { return Sm2Core.compressPublicKey(key); }
    public static byte[] uncompressPublicKey(byte[] key) { return Sm2Core.uncompressPublicKey(key); }

    /** Uses DER SEQUENCE(x,y,C3,C2); empty plaintext is rejected. */
    public static byte[] encrypt(byte[] publicKey, byte[] plaintext) throws IOException {
        return encrypt(publicKey, plaintext, SM2CiphertextFormat.DER);
    }
    public static byte[] encrypt(byte[] publicKey, byte[] plaintext, SM2CiphertextFormat format) throws IOException {
        return Sm2Core.encrypt(publicKey, plaintext, format);
    }
    public static byte[] decrypt(byte[] privateKey, byte[] ciphertext) throws IOException {
        return decrypt(privateKey, ciphertext, SM2CiphertextFormat.DER);
    }
    public static byte[] decrypt(byte[] privateKey, byte[] ciphertext, SM2CiphertextFormat format) throws CipherException {
        return Sm2Core.decrypt(privateKey, ciphertext, format);
    }
    /** Re-encodes a structurally valid standard-curve ciphertext; does not authenticate it. */
    public static byte[] convertCiphertext(byte[] ciphertext, SM2CiphertextFormat from, SM2CiphertextFormat to) throws IOException {
        return Sm2Core.convertCiphertext(ciphertext, from, to);
    }

    /** Signs SM3(ZA || message) with a fresh cryptographic nonce and canonical DER output. */
    public static byte[] sign(byte[] userId, byte[] privateKey, byte[] message) throws IOException {
        return sign(userId, privateKey, message, SM2SignatureFormat.DER);
    }
    public static byte[] sign(byte[] userId, byte[] privateKey, byte[] message, SM2SignatureFormat format) throws IOException {
        return Sm2Core.sign(userId, privateKey, message, format, false);
    }
    public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] message, byte[] signature) throws IOException {
        return verifySign(userId, publicKey, message, signature, SM2SignatureFormat.DER);
    }
    public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] message, byte[] signature, SM2SignatureFormat format) {
        return Sm2Core.verify(userId, publicKey, message, signature, format, false);
    }
    public static byte[] convertSignature(byte[] signature, SM2SignatureFormat from, SM2SignatureFormat to) throws IOException {
        return Sm2Core.convertSignature(signature, from, to);
    }
    /** Computes e = SM3(ZA || message) for a hardware or prehashed protocol boundary. */
    public static byte[] signatureDigest(byte[] userId, byte[] publicKey, byte[] message) {
        return Sm2Core.signatureDigest(userId, publicKey, message);
    }
    /** Advanced API: signs exactly the 32-byte e supplied, with no additional hash or ZA. */
    public static byte[] signPrecomputedDigest(byte[] privateKey, byte[] digest, SM2SignatureFormat format) throws IOException {
        return Sm2Core.sign(new byte[0], privateKey, digest, format, true);
    }
    public static boolean verifyPrecomputedDigest(byte[] publicKey, byte[] digest, byte[] signature, SM2SignatureFormat format) {
        return Sm2Core.verify(new byte[0], publicKey, digest, signature, format, true);
    }

    public static byte[] publicKeyToSpki(byte[] key) throws IOException { return Sm2Core.exportPublicKey(key); }
    public static byte[] publicKeyFromSpki(byte[] der) throws IOException { return Sm2Core.importPublicKey(der); }
    public static byte[] privateKeyToPkcs8(byte[] key) throws IOException { return Sm2Core.exportPrivateKey(key); }
    public static byte[] privateKeyFromPkcs8(byte[] der) throws IOException { return Sm2Core.importPrivateKey(der); }
    public static String publicKeyToPem(byte[] key) throws IOException { return Pem.encode("PUBLIC KEY", publicKeyToSpki(key)); }
    public static byte[] publicKeyFromPem(String pem) throws IOException { return publicKeyFromSpki(Pem.decode("PUBLIC KEY", pem)); }
    public static String privateKeyToPem(byte[] key) throws IOException { return Pem.encode("PRIVATE KEY", privateKeyToPkcs8(key)); }
    public static byte[] privateKeyFromPem(String pem) throws IOException { return privateKeyFromPkcs8(Pem.decode("PRIVATE KEY", pem)); }
}
