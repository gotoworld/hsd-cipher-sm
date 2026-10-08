package com.heshidai.security.cipher;

/** Canonical DER SEQUENCE(r,s), or exactly 32 unsigned bytes of r followed by 32 of s. */
public enum SM2SignatureFormat {
    DER,
    PLAIN_RS
}
