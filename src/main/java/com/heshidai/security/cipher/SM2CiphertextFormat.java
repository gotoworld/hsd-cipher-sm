package com.heshidai.security.cipher;

/** Explicit SM2 wire formats. Raw C1 is always the 65-byte uncompressed point, including 04. */
public enum SM2CiphertextFormat {
    DER,
    RAW_C1C3C2,
    RAW_C1C2C3
}
