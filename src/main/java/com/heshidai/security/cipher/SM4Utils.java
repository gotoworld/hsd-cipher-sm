package com.heshidai.security.cipher;

import com.heshidai.security.cipher.internal.Checks;
import com.heshidai.security.cipher.internal.TextCodec;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Mutable compatibility wrapper for Base64 ECB/CBC text. Not thread-safe.
 * Defaults to UTF-8. Select GBK explicitly for old data; prefer SM4.seal/open for new data.
 */
@Deprecated
public class SM4Utils {
    private String secretKey = "";
    private String iv = "";
    private boolean hexString;
    private Charset charset = StandardCharsets.UTF_8;
    private Charset keyCharset = StandardCharsets.UTF_8;

    public String getSecretKey() { return secretKey; }
    public void setSecretKey(String value) { secretKey = Checks.required(value, "secret key"); }
    public String getIv() { return iv; }
    public void setIv(String value) { iv = Checks.required(value, "IV"); }
    public boolean isHexString() { return hexString; }
    public void setHexString(boolean value) { hexString = value; }
    public Charset getCharset() { return charset; }
    public void setCharset(Charset value) { charset = Checks.required(value, "charset"); }
    public Charset getKeyCharset() { return keyCharset; }
    public void setKeyCharset(Charset value) { keyCharset = Checks.required(value, "key charset"); }

    private byte[] key() { return hexString ? Hex.decode(secretKey) : TextCodec.encode(secretKey, keyCharset); }
    private byte[] iv() { return hexString ? Hex.decode(iv) : TextCodec.encode(iv, keyCharset); }
    private byte[] decode(String value) {
        Checks.required(value, "Base64 ciphertext");
        // Original encoder emitted line breaks; allow only CR/LF rather than arbitrary ignored characters.
        return Base64.getDecoder().decode(value.replace("\r", "").replace("\n", ""));
    }
    public String encryptData_ECB(String plaintext) {
        return Base64.getEncoder().encodeToString(SM4.encryptEcb(key(), TextCodec.encode(plaintext, charset), SM4.Padding.PKCS7));
    }
    public String decryptData_ECB(String ciphertext) {
        try { return TextCodec.decode(SM4.decryptEcb(key(), decode(ciphertext), SM4.Padding.PKCS7), charset); }
        catch (CipherException e) { throw new IllegalArgumentException("SM4 ciphertext could not be decrypted", e); }
    }
    public String encryptData_CBC(String plaintext) {
        return Base64.getEncoder().encodeToString(SM4.encryptCbc(key(), iv(), TextCodec.encode(plaintext, charset), SM4.Padding.PKCS7));
    }
    public String decryptData_CBC(String ciphertext) {
        try { return TextCodec.decode(SM4.decryptCbc(key(), iv(), decode(ciphertext), SM4.Padding.PKCS7), charset); }
        catch (CipherException e) { throw new IllegalArgumentException("SM4 ciphertext could not be decrypted", e); }
    }
}
