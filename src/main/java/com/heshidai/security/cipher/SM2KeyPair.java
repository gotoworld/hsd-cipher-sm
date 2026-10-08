package com.heshidai.security.cipher;

/** Raw standard-curve keys. Accessors return copies; this object must be treated as a secret. */
public final class SM2KeyPair {
    private final byte[] privateKey;
    private final byte[] publicKey;

    SM2KeyPair(byte[] privateKey, byte[] publicKey) {
        this.privateKey = privateKey.clone();
        this.publicKey = publicKey.clone();
    }

    public byte[] getPrivateKey() { return privateKey.clone(); }
    public byte[] getPublicKey() { return publicKey.clone(); }
}
