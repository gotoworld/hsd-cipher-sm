package com.heshidai.security.cipher;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import static com.heshidai.security.cipher.Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit opt-in: mvn -Dopenssl.integration=true test. Requires OpenSSL 3.x on PATH. */
@EnabledIfSystemProperty(named = "openssl.integration", matches = "true")
class OpenSSLInteropTest {
    @TempDir Path work;
    private String openssl(String... args) throws Exception {
        List<String> command = new ArrayList<>(); command.add("openssl"); command.addAll(Arrays.asList(args));
        Path log = Files.createTempFile(work, "openssl-", ".log");
        Process process = new ProcessBuilder(command).directory(work.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IOException("OpenSSL timed out"); }
        String output = new String(Files.readAllBytes(log), StandardCharsets.UTF_8);
        assertEquals(0, process.exitValue(), command + "\n" + output);
        return output;
    }
    private void put(String name, byte[] value) throws IOException { Files.write(work.resolve(name), value); }
    private byte[] get(String name) throws IOException { return Files.readAllBytes(work.resolve(name)); }

    @Test void javaAndOpenSslExchangeSm2KeysCiphertextsAndSignatures() throws Exception {
        assertTrue(openssl("version").startsWith("OpenSSL 3."), "OpenSSL 3.x is required");
        SM2KeyPair keys = SM2Utils.generateKeyPair(); byte[] message = utf8("Java/OpenSSL 国密 interoperability🙂");
        byte[] id = SM2Utils.defaultUserId();
        put("private.pem", utf8(SM2Utils.privateKeyToPem(keys.getPrivateKey())));
        put("public.pem", utf8(SM2Utils.publicKeyToPem(keys.getPublicKey()))); put("message.bin", message);
        put("java.ct", SM2Utils.encrypt(keys.getPublicKey(), message));
        openssl("pkeyutl", "-decrypt", "-inkey", "private.pem", "-in", "java.ct", "-out", "openssl.plain");
        assertArrayEquals(message, get("openssl.plain"));
        openssl("pkeyutl", "-encrypt", "-pubin", "-inkey", "public.pem", "-in", "message.bin", "-out", "openssl.ct");
        assertArrayEquals(message, SM2Utils.decrypt(keys.getPrivateKey(), get("openssl.ct")));
        put("java.sig", SM2Utils.sign(id, keys.getPrivateKey(), message));
        assertTrue(openssl("dgst", "-sm3", "-verify", "public.pem", "-sigopt", "distid:1234567812345678",
            "-signature", "java.sig", "message.bin").contains("Verified OK"));
        openssl("dgst", "-sm3", "-sign", "private.pem", "-sigopt", "distid:1234567812345678", "-out", "openssl.sig", "message.bin");
        assertTrue(SM2Utils.verifySign(id, keys.getPublicKey(), message, get("openssl.sig")));
        openssl("genpkey", "-algorithm", "SM2", "-out", "generated.pem");
        openssl("pkey", "-in", "generated.pem", "-pubout", "-out", "generated-public.pem");
        byte[] importedPrivate = SM2Utils.privateKeyFromPem(new String(get("generated.pem"), StandardCharsets.US_ASCII));
        byte[] importedPublic = SM2Utils.publicKeyFromPem(new String(get("generated-public.pem"), StandardCharsets.US_ASCII));
        assertArrayEquals(importedPublic, SM2Utils.publicKeyFromPrivateKey(importedPrivate));
        put("imported.ct", SM2Utils.encrypt(importedPublic, message));
        openssl("pkeyutl", "-decrypt", "-inkey", "generated.pem", "-in", "imported.ct", "-out", "imported.plain");
        assertArrayEquals(message, get("imported.plain"));
    }

    @Test void sm3HmacAndSm4CbcMatchIndependentOpenSsl() throws Exception {
        byte[] key = Hex.decode("0123456789abcdeffedcba9876543210"), iv = new byte[16], message = utf8("independent implementation sample");
        put("message.bin", message);
        assertTrue(openssl("dgst", "-sm3", "message.bin").trim().endsWith(Hex.encode(SM3.digest(message))));
        assertTrue(openssl("dgst", "-sm3", "-mac", "HMAC", "-macopt", "hexkey:" + Hex.encode(key), "message.bin")
            .trim().endsWith(Hex.encode(SM3.hmac(key, message))));
        byte[] javaCiphertext = SM4.encryptCbc(key, iv, message, SM4.Padding.PKCS7); put("java.cbc", javaCiphertext);
        openssl("enc", "-sm4-cbc", "-nosalt", "-K", Hex.encode(key), "-iv", Hex.encode(iv), "-in", "message.bin", "-out", "openssl.cbc");
        assertArrayEquals(javaCiphertext, get("openssl.cbc"));
        openssl("enc", "-d", "-sm4-cbc", "-nosalt", "-K", Hex.encode(key), "-iv", Hex.encode(iv), "-in", "java.cbc", "-out", "openssl.plain");
        assertArrayEquals(message, get("openssl.plain"));
    }
}
