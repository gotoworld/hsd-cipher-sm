package com.heshidai.security.cipher;

import com.heshidai.security.cipher.internal.Checks;

/** Mutable, non-thread-safe SM3 state. doFinal writes at outOff and resets the state. */
public class SM3Digest {
    private final org.bouncycastle.crypto.digests.SM3Digest delegate;
    public SM3Digest() { delegate = new org.bouncycastle.crypto.digests.SM3Digest(); }
    public SM3Digest(SM3Digest other) {
        delegate = new org.bouncycastle.crypto.digests.SM3Digest(Checks.required(other, "digest").delegate);
    }
    public int getDigestSize() { return delegate.getDigestSize(); }
    public void update(byte input) { delegate.update(input); }
    public void update(byte[] input, int offset, int length) {
        Checks.range(input, offset, length);
        delegate.update(input, offset, length);
    }
    public int doFinal(byte[] output, int offset) {
        Checks.range(output, offset, getDigestSize());
        return delegate.doFinal(output, offset);
    }
    public void reset() { delegate.reset(); }
}
