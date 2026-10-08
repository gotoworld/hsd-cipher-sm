package com.heshidai.security.cipher;

import com.heshidai.security.cipher.legacy.LegacySM2;
import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static com.heshidai.security.cipher.Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class SM2Test {
    private static final BigInteger N = GMNamedCurves.getByName("sm2p256v1").getN();
    private static byte[] unsigned(BigInteger n) { return org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, n); }
    private static byte[] der(BigInteger r, BigInteger s) throws IOException {
        return new DERSequence(new ASN1Encodable[] {new ASN1Integer(r), new ASN1Integer(s)}).getEncoded();
    }
    private static byte[] field(byte[] original, int index, ASN1Encodable replacement, boolean extra) throws IOException {
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(original));
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < seq.size(); i++) v.add(i == index ? replacement : seq.getObjectAt(i));
        if (extra) v.add(new ASN1Integer(1));
        return new DERSequence(v).getEncoded();
    }

    @ParameterizedTest @EnumSource(SM2CiphertextFormat.class)
    void encryptedFormatsAuthenticateAndRoundTrip(SM2CiphertextFormat format) throws Exception {
        SM2KeyPair keys = SM2Utils.generateKeyPair(); byte[] input = utf8("国密🙂\u0000binary"); byte[] snapshot = input.clone();
        byte[] encrypted = SM2Utils.encrypt(keys.getPublicKey(), input, format);
        assertArrayEquals(input, SM2Utils.decrypt(keys.getPrivateKey(), encrypted, format));
        assertArrayEquals(snapshot, input);
        assertFalse(Arrays.equals(encrypted, SM2Utils.encrypt(keys.getPublicKey(), input, format)));
        byte[] raw = SM2Utils.convertCiphertext(encrypted, format, SM2CiphertextFormat.RAW_C1C3C2);
        for (int at : new int[] {1, 65, 97}) {
            assertThrows(CipherException.class, () -> SM2Utils.decrypt(keys.getPrivateKey(), change(raw, at), SM2CiphertextFormat.RAW_C1C3C2));
        }
        assertThrows(CipherException.class, () -> SM2Utils.decrypt(SM2Utils.generateKeyPair().getPrivateKey(), encrypted, format));
        for (SM2CiphertextFormat target : SM2CiphertextFormat.values()) {
            byte[] converted = SM2Utils.convertCiphertext(encrypted, format, target);
            assertArrayEquals(input, SM2Utils.decrypt(keys.getPrivateKey(), converted, target));
            assertArrayEquals(encrypted, SM2Utils.convertCiphertext(converted, target, format));
        }
    }

    @Test void ciphertextParserRejectsMalformedAndEquivalentUnsafeForms() throws Exception {
        SM2KeyPair keys = SM2Utils.generateKeyPair(); byte[] ct = SM2Utils.encrypt(keys.getPublicKey(), utf8("parser"));
        byte[] trailing = Arrays.copyOf(ct, ct.length + 1);
        ASN1Sequence seq = ASN1Sequence.getInstance(ct);
        byte[] ber = new BERSequence(seq.toArray()).getEncoded(ASN1Encoding.BER);
        byte[] shortSeq = new DERSequence(new ASN1Encodable[] {seq.getObjectAt(0)}).getEncoded();
        byte[] changedC3 = field(ct, 2, new DEROctetString(new byte[32]), false);
        byte[] changedC2 = field(ct, 3, new DEROctetString(utf8("tamper")), false);
        byte[][] bad = {trailing, ber, shortSeq, Arrays.copyOf(ct, ct.length - 1),
            field(ct, 0, new ASN1Integer(-1), false),
            field(ct, 0, new ASN1Integer(GMNamedCurves.getByName("sm2p256v1").getCurve().getField().getCharacteristic()), false),
            field(ct, 2, new DEROctetString(new byte[31]), false),
            field(ct, 3, new DEROctetString(new byte[0]), false),
            field(ct, 2, new ASN1Integer(1), false), field(ct, -1, null, true), changedC3, changedC2};
        for (byte[] value : bad) assertThrows(CipherException.class, () -> SM2Utils.decrypt(keys.getPrivateKey(), value));
        byte[] hybrid = SM2Utils.convertCiphertext(ct, SM2CiphertextFormat.DER, SM2CiphertextFormat.RAW_C1C3C2);
        hybrid[0] = (byte) (6 | (hybrid[64] & 1));
        assertThrows(CipherException.class, () -> SM2Utils.decrypt(keys.getPrivateKey(), hybrid, SM2CiphertextFormat.RAW_C1C3C2));
    }

    @ParameterizedTest @EnumSource(SM2SignatureFormat.class)
    void signaturesAreRandomizedAndRejectInvalidInputs(SM2SignatureFormat format) throws Exception {
        SM2KeyPair keys = SM2Utils.generateKeyPair(); byte[] id = SM2Utils.defaultUserId(), msg = utf8("signature🙂");
        byte[] sig = SM2Utils.sign(id, keys.getPrivateKey(), msg, format);
        assertTrue(SM2Utils.verifySign(id, keys.getPublicKey(), msg, sig, format));
        assertFalse(Arrays.equals(sig, SM2Utils.sign(id, keys.getPrivateKey(), msg, format)));
        assertFalse(SM2Utils.verifySign(change(id, 0), keys.getPublicKey(), msg, sig, format));
        assertFalse(SM2Utils.verifySign(id, keys.getPublicKey(), change(msg, 0), sig, format));
        assertFalse(SM2Utils.verifySign(id, SM2Utils.generateKeyPair().getPublicKey(), msg, sig, format));
        assertFalse(SM2Utils.verifySign(id, keys.getPublicKey(), msg, null, format));
        assertFalse(SM2Utils.verifySign(id, keys.getPublicKey(), msg, new byte[0], format));
        assertFalse(SM2Utils.verifySign(id, keys.getPublicKey(), msg, Arrays.copyOf(sig, sig.length - 1), format));
        SM2SignatureFormat other = format == SM2SignatureFormat.DER ? SM2SignatureFormat.PLAIN_RS : SM2SignatureFormat.DER;
        byte[] converted = SM2Utils.convertSignature(sig, format, other);
        assertTrue(SM2Utils.verifySign(id, keys.getPublicKey(), msg, converted, other));
        assertArrayEquals(sig, SM2Utils.convertSignature(converted, other, format));
        byte[] canonical = SM2Utils.convertSignature(sig, format, SM2SignatureFormat.DER);
        BigInteger[] rs = StandardDSAEncoding.INSTANCE.decode(N, canonical);
        for (byte[] bad : new byte[][] {der(rs[0], rs[1].add(N)), der(BigInteger.ZERO, rs[1]),
            der(rs[0], N), der(BigInteger.valueOf(-1), rs[1]), Arrays.copyOf(canonical, canonical.length + 1),
            new BERSequence(ASN1Sequence.getInstance(canonical).toArray()).getEncoded(ASN1Encoding.BER)}) {
            assertFalse(SM2Utils.verifySign(id, keys.getPublicKey(), msg, bad, SM2SignatureFormat.DER));
        }
        BigInteger oldK = new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16);
        BigInteger denominator = rs[0].add(rs[1]).mod(N);
        if (denominator.signum() != 0) {
            BigInteger recovered = oldK.subtract(rs[1]).multiply(denominator.modInverse(N)).mod(N);
            assertNotEquals(new BigInteger(1, keys.getPrivateKey()), recovered);
        }
    }

    @Test void standardProviderVectorAndPrehashedBoundaryAgree() throws Exception {
        // BC r1rv86 SM2SignerTest.doSignerTestFpStandardSM3, a fixed non-production vector.
        byte[] key = Hex.decode("110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC");
        byte[] publicKey = SM2Utils.publicKeyFromPrivateKey(key), id = utf8("sm2test@example.com"), msg = utf8("hi chappy");
        byte[] plain = Hex.decode("05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA"
            + "E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993");
        assertTrue(SM2Utils.verifySign(id, publicKey, msg, plain, SM2SignatureFormat.PLAIN_RS));
        byte[] e = SM2Utils.signatureDigest(id, publicKey, msg);
        assertTrue(SM2Utils.verifyPrecomputedDigest(publicKey, e, plain, SM2SignatureFormat.PLAIN_RS));
        byte[] sig = SM2Utils.signPrecomputedDigest(key, e, SM2SignatureFormat.DER);
        assertTrue(SM2Utils.verifySign(id, publicKey, msg, sig));
        assertTrue(SM2Utils.verifyPrecomputedDigest(publicKey, e, SM2Utils.sign(id, key, msg), SM2SignatureFormat.DER));
        assertFalse(SM2Utils.verifyPrecomputedDigest(publicKey, change(e, 0), sig, SM2SignatureFormat.DER));
        assertThrows(IllegalArgumentException.class, () -> SM2Utils.signPrecomputedDigest(key, new byte[31], SM2SignatureFormat.DER));
    }

    @Test void keysValidateUnsignedRangesAndDefensiveCopies() throws Exception {
        byte[] high = Hex.decode("8000000000000000000000000000000000000000000000000000000000000001");
        byte[] pub = SM2Utils.publicKeyFromPrivateKey(high), id = SM2Utils.defaultUserId();
        byte[] sig = SM2Utils.sign(id, high, new byte[0]);
        assertTrue(SM2Utils.verifySign(id, pub, new byte[0], sig));
        assertArrayEquals(pub, SM2Utils.uncompressPublicKey(SM2Utils.compressPublicKey(pub)));
        assertThrows(IllegalArgumentException.class, () -> SM2Utils.sign(null, high, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> SM2Utils.sign(new byte[8192], high, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> SM2Utils.encrypt(pub, new byte[0]));
        for (byte[] bad : new byte[][] {new byte[32], unsigned(N), new byte[31], new byte[33]}) {
            assertThrows(IllegalArgumentException.class, () -> SM2Utils.publicKeyFromPrivateKey(bad));
        }
        byte[] last = unsigned(N.subtract(BigInteger.ONE));
        assertThrows(IllegalArgumentException.class, () -> SM2Utils.sign(id, last, utf8("message")));
        assertArrayEquals(utf8("decrypt"), SM2Utils.decrypt(last, SM2Utils.encrypt(SM2Utils.publicKeyFromPrivateKey(last), utf8("decrypt"))));
        byte[] hybrid = pub.clone(); hybrid[0] = (byte) (6 | (hybrid[64] & 1));
        assertThrows(IllegalArgumentException.class, () -> SM2Utils.uncompressPublicKey(hybrid));
        SM2KeyPair generated = SM2Utils.generateKeyPair(); byte[] exposed = generated.getPrivateKey(); exposed[0] ^= 1;
        assertFalse(Arrays.equals(exposed, generated.getPrivateKey()));
        assertArrayEquals(SM2Utils.publicKeyFromPrivateKey(generated.getPrivateKey()), generated.getPublicKey());
    }

    @Test void keyFilesRoundTripAndRejectOtherCurvesAndTrailingObjects() throws Exception {
        SM2KeyPair keys = SM2Utils.generateKeyPair();
        assertArrayEquals(keys.getPrivateKey(), SM2Utils.privateKeyFromPkcs8(SM2Utils.privateKeyToPkcs8(keys.getPrivateKey())));
        assertArrayEquals(keys.getPublicKey(), SM2Utils.publicKeyFromSpki(SM2Utils.publicKeyToSpki(keys.getPublicKey())));
        assertArrayEquals(keys.getPrivateKey(), SM2Utils.privateKeyFromPem(SM2Utils.privateKeyToPem(keys.getPrivateKey())));
        String pem = SM2Utils.publicKeyToPem(keys.getPublicKey());
        assertArrayEquals(keys.getPublicKey(), SM2Utils.publicKeyFromPem(pem.replace("\n", "\r\n")));
        assertThrows(IOException.class, () -> SM2Utils.publicKeyFromPem(pem + pem));
        assertThrows(IOException.class, () -> SM2Utils.privateKeyFromPem(pem));
        byte[] spki = SM2Utils.publicKeyToSpki(keys.getPublicKey());
        assertThrows(IOException.class, () -> SM2Utils.publicKeyFromSpki(Arrays.copyOf(spki, spki.length + 1)));
        byte[] wrongCurve = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
            X9ObjectIdentifiers.prime256v1), keys.getPublicKey()).getEncoded();
        assertThrows(IOException.class, () -> SM2Utils.publicKeyFromSpki(wrongCurve));
        assertThrows(IOException.class, () -> SM2Utils.privateKeyFromPkcs8(new DERSequence().getEncoded()));
        assertThrows(IOException.class, () -> SM2Utils.publicKeyFromSpki(new DERSequence().getEncoded()));
    }

    @Test void legacyReadOnlyMigrationValidatesOriginalCiphertextAndSignature() throws Exception {
        byte[] privateKey = legacyHex("private.hex"), publicKey = legacyHex("public.hex"), ciphertext = legacyHex("ciphertext.der.hex");
        byte[] message = legacyHex("message.hex"), signature = legacyHex("signature.der.hex"), id = utf8(legacy("id.utf8"));
        assertArrayEquals(message, LegacySM2.decrypt(privateKey, ciphertext));
        byte[] leading = new byte[33]; System.arraycopy(privateKey, 0, leading, 1, 32);
        assertArrayEquals(message, LegacySM2.decrypt(leading, ciphertext));
        leading[0] = 1; assertThrows(IllegalArgumentException.class, () -> LegacySM2.decrypt(leading, ciphertext));
        assertTrue(LegacySM2.verifySignature(id, publicKey, message, signature));
        assertFalse(LegacySM2.verifySignature(change(id, 0), publicKey, message, signature));
        for (byte[] bad : new byte[][] {field(ciphertext, 2, new DEROctetString(new byte[32]), false),
            field(ciphertext, 3, new DEROctetString(change(message, 0)), false),
            field(ciphertext, 0, new ASN1Integer(-1), false), field(ciphertext, -1, null, true),
            Arrays.copyOf(ciphertext, ciphertext.length + 1)}) {
            assertThrows(CipherException.class, () -> LegacySM2.decrypt(privateKey, bad));
        }
        assertThrows(IllegalArgumentException.class, () -> SM2Utils.encrypt(publicKey, message));
        for (java.lang.reflect.Method method : LegacySM2.class.getDeclaredMethods()) {
            assertTrue(method.getName().equals("decrypt") || method.getName().equals("verifySignature"));
        }
    }

    @Test void productionEntryPointsNeverWriteToStdoutOrStderr() throws Exception {
        PrintStream stdout = System.out, stderr = System.err;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(captured)); System.setErr(new PrintStream(captured));
            SM2KeyPair keys = SM2Utils.generateKeyPair(); byte[] msg = utf8("private message");
            byte[] sig = SM2Utils.sign(SM2Utils.defaultUserId(), keys.getPrivateKey(), msg);
            assertTrue(SM2Utils.verifySign(SM2Utils.defaultUserId(), keys.getPublicKey(), msg, sig));
            byte[] ct = SM2Utils.encrypt(keys.getPublicKey(), msg); SM2Utils.decrypt(keys.getPrivateKey(), ct);
            assertThrows(CipherException.class, () -> SM2Utils.decrypt(keys.getPrivateKey(), change(ct, ct.length - 1)));
            SM4Utils wrapper = new SM4Utils(); wrapper.setSecretKey("0123456789abcdef");
            wrapper.decryptData_ECB(wrapper.encryptData_ECB("message"));
            assertThrows(IllegalArgumentException.class, () -> wrapper.decryptData_ECB("invalid!"));
        } finally { System.setOut(stdout); System.setErr(stderr); }
        assertEquals(0, captured.size());
    }

    @Test void unauthenticatedLowLevelClassesAreAbsent() {
        for (String name : new String[] {"SM2", "Cipher", "SM2Result", "SM4_Context"}) {
            assertThrows(ClassNotFoundException.class, () -> Class.forName("com.heshidai.security.cipher." + name));
        }
    }
}
