package com.heshidai.security.cipher.internal;

import java.io.IOException;
import java.util.Base64;

/** Internal strict, single-object PEM codec. Encrypted and SEC1 private-key PEM are not accepted. */
public final class Pem {
    private Pem() { }
    public static String encode(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n"
            + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
            + "\n-----END " + label + "-----\n";
    }
    public static byte[] decode(String label, String pem) throws IOException {
        Checks.required(pem, "PEM");
        if (pem.length() > 24000) throw new IOException("PEM is too large");
        String normalized = pem.replace("\r\n", "\n");
        String begin = "-----BEGIN " + label + "-----\n";
        String end = "\n-----END " + label + "-----";
        if (normalized.endsWith("\n")) normalized = normalized.substring(0, normalized.length() - 1);
        if (!normalized.startsWith(begin) || !normalized.endsWith(end)) throw new IOException("Unexpected PEM object");
        String body = normalized.substring(begin.length(), normalized.length() - end.length()).replace("\n", "");
        try {
            byte[] decoded = Base64.getDecoder().decode(body);
            if (!Base64.getEncoder().encodeToString(decoded).equals(body)) throw new IOException("Noncanonical PEM Base64");
            return decoded;
        } catch (IllegalArgumentException e) { throw new IOException("Invalid PEM Base64", e); }
    }
}
