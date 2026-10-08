package com.heshidai.security.cipher;

import java.io.IOException;

/** A ciphertext could not be decrypted or authenticated. No partial plaintext is returned. */
public final class CipherException extends IOException {
    private static final long serialVersionUID = 1L;

    public CipherException() {
        super("Ciphertext could not be decrypted or authenticated");
    }

    public CipherException(Throwable cause) {
        super("Ciphertext could not be decrypted or authenticated", cause);
    }
}
