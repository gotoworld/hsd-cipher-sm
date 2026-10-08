package com.heshidai.security.cipher.internal;

import com.heshidai.security.cipher.CipherException;
import com.heshidai.security.cipher.SM2CiphertextFormat;
import com.heshidai.security.cipher.SM2SignatureFormat;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.SM2KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

/** Internal implementation. Only the standard curve can generate keys, encrypt or sign. */
public final class Sm2Core {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ECDomainParameters STANDARD = new ECNamedDomainParameters(
        GMObjectIdentifiers.sm2p256v1, GMNamedCurves.getByName("sm2p256v1"));
    private static final ECDomainParameters LEGACY = legacyDomain();
    private Sm2Core() { }

    private static ECDomainParameters legacyDomain() {
        BigInteger p = hex("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3");
        BigInteger a = hex("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498");
        BigInteger b = hex("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A");
        BigInteger n = hex("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7");
        ECCurve curve = new ECCurve.Fp(p, a, b, n, BigInteger.ONE);
        ECPoint g = curve.validatePoint(
            hex("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
            hex("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"));
        return new ECDomainParameters(curve, g, n, BigInteger.ONE);
    }

    private static BigInteger hex(String value) { return new BigInteger(value, 16); }

    private static ECPrivateKeyParameters privateKey(byte[] raw, ECDomainParameters domain, boolean signing) {
        Checks.length(raw, 32, "raw private key");
        BigInteger d = new BigInteger(1, raw);
        BigInteger upper = signing ? domain.getN().subtract(BigInteger.ONE) : domain.getN();
        if (d.signum() <= 0 || d.compareTo(upper) >= 0) throw new IllegalArgumentException("SM2 private key out of range");
        return new ECPrivateKeyParameters(d, domain);
    }

    private static ECPublicKeyParameters publicKey(byte[] raw, ECDomainParameters domain) {
        Checks.required(raw, "raw public key");
        if (!((raw.length == 65 && raw[0] == 4) || (raw.length == 33 && (raw[0] == 2 || raw[0] == 3)))) {
            throw new IllegalArgumentException("SM2 public key must be a compressed or uncompressed SEC1 point");
        }
        return new ECPublicKeyParameters(domain.getCurve().decodePoint(raw), domain);
    }

    private static byte[] legacyPrivateKey(byte[] raw) {
        Checks.required(raw, "legacy private key");
        if (raw.length < 1 || raw.length > 33 || (raw.length == 33 && raw[0] != 0)) {
            throw new IllegalArgumentException("Invalid unsigned legacy private key encoding");
        }
        return BigIntegers.asUnsignedByteArray(32, new BigInteger(1, raw));
    }

    public static byte[] generatePrivateKey() {
        SM2KeyPairGenerator generator = new SM2KeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(STANDARD, RANDOM));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        return BigIntegers.asUnsignedByteArray(32, ((ECPrivateKeyParameters) pair.getPrivate()).getD());
    }

    public static byte[] derivePublicKey(byte[] rawPrivateKey) {
        BigInteger d = privateKey(rawPrivateKey, STANDARD, false).getD();
        return STANDARD.getG().multiply(d).normalize().getEncoded(false);
    }

    public static byte[] compressPublicKey(byte[] raw) { return publicKey(raw, STANDARD).getQ().getEncoded(true); }
    public static byte[] uncompressPublicKey(byte[] raw) { return publicKey(raw, STANDARD).getQ().getEncoded(false); }

    private static ASN1Sequence sequence(byte[] der) throws IOException {
        Checks.required(der, "DER");
        ASN1Primitive value = ASN1Primitive.fromByteArray(der);
        if (!(value instanceof ASN1Sequence) || !Arrays.equals(der, value.getEncoded(ASN1Encoding.DER))) {
            throw new IOException("Expected a canonical DER sequence");
        }
        return (ASN1Sequence) value;
    }

    private static byte[] normalizeCiphertext(byte[] data, SM2CiphertextFormat format, ECDomainParameters domain) throws IOException {
        Checks.required(data, "ciphertext");
        Checks.required(format, "ciphertext format");
        byte[] canonical;
        if (format == SM2CiphertextFormat.DER) {
            ASN1Sequence seq = sequence(data);
            if (seq.size() != 4 || !(seq.getObjectAt(0) instanceof ASN1Integer)
                || !(seq.getObjectAt(1) instanceof ASN1Integer)
                || !(seq.getObjectAt(2) instanceof ASN1OctetString)
                || !(seq.getObjectAt(3) instanceof ASN1OctetString)) throw new IOException("Invalid SM2 ciphertext structure");
            BigInteger x = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger y = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            BigInteger p = domain.getCurve().getField().getCharacteristic();
            if (x.signum() < 0 || y.signum() < 0 || x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
                throw new IOException("SM2 coordinate out of range");
            }
            byte[] c1 = domain.getCurve().validatePoint(x, y).getEncoded(false);
            byte[] c3 = ((ASN1OctetString) seq.getObjectAt(2)).getOctets();
            byte[] c2 = ((ASN1OctetString) seq.getObjectAt(3)).getOctets();
            if (c3.length != 32 || c2.length == 0) throw new IOException("Invalid SM2 ciphertext lengths");
            canonical = new byte[Math.addExact(97, c2.length)];
            System.arraycopy(c1, 0, canonical, 0, 65);
            System.arraycopy(c3, 0, canonical, 65, 32);
            System.arraycopy(c2, 0, canonical, 97, c2.length);
        } else {
            if (data.length < 98 || data[0] != 4) throw new IOException("Invalid raw SM2 ciphertext");
            canonical = data.clone();
            if (format == SM2CiphertextFormat.RAW_C1C2C3) {
                int c2Length = data.length - 97;
                System.arraycopy(data, 65 + c2Length, canonical, 65, 32);
                System.arraycopy(data, 65, canonical, 97, c2Length);
            }
        }
        publicKey(Arrays.copyOf(canonical, 65), domain);
        return canonical;
    }

    private static byte[] encodeCiphertext(byte[] canonical, SM2CiphertextFormat format) throws IOException {
        Checks.required(format, "ciphertext format");
        if (format == SM2CiphertextFormat.RAW_C1C3C2) return canonical.clone();
        int c2Length = canonical.length - 97;
        if (format == SM2CiphertextFormat.RAW_C1C2C3) {
            byte[] raw = canonical.clone();
            System.arraycopy(canonical, 97, raw, 65, c2Length);
            System.arraycopy(canonical, 65, raw, 65 + c2Length, 32);
            return raw;
        }
        ASN1EncodableVector fields = new ASN1EncodableVector(4);
        fields.add(new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(canonical, 1, 33))));
        fields.add(new ASN1Integer(new BigInteger(1, Arrays.copyOfRange(canonical, 33, 65))));
        fields.add(new DEROctetString(Arrays.copyOfRange(canonical, 65, 97)));
        fields.add(new DEROctetString(Arrays.copyOfRange(canonical, 97, canonical.length)));
        return new DERSequence(fields).getEncoded(ASN1Encoding.DER);
    }

    public static byte[] encrypt(byte[] publicKey, byte[] plaintext, SM2CiphertextFormat format) throws IOException {
        Checks.required(plaintext, "plaintext");
        Checks.required(format, "ciphertext format");
        if (plaintext.length == 0) throw new IllegalArgumentException("SM2 plaintext must not be empty");
        SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        engine.init(true, new ParametersWithRandom(publicKey(publicKey, STANDARD), RANDOM));
        try {
            return encodeCiphertext(engine.processBlock(plaintext, 0, plaintext.length), format);
        } catch (CryptoException e) { throw new IOException("SM2 encryption failed", e); }
    }

    private static byte[] decrypt(byte[] key, byte[] ciphertext, SM2CiphertextFormat format, ECDomainParameters domain) throws CipherException {
        ECPrivateKeyParameters privateKey = privateKey(key, domain, false);
        Checks.required(ciphertext, "ciphertext");
        Checks.required(format, "ciphertext format");
        try {
            byte[] canonical = normalizeCiphertext(ciphertext, format, domain);
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(false, privateKey);
            return engine.processBlock(canonical, 0, canonical.length);
        } catch (IOException | RuntimeException | CryptoException e) { throw new CipherException(e); }
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext, SM2CiphertextFormat format) throws CipherException {
        return decrypt(key, ciphertext, format, STANDARD);
    }

    public static byte[] decryptLegacy(byte[] key, byte[] ciphertext) throws CipherException {
        return decrypt(legacyPrivateKey(key), ciphertext, SM2CiphertextFormat.DER, LEGACY);
    }

    public static byte[] convertCiphertext(byte[] data, SM2CiphertextFormat from, SM2CiphertextFormat to) throws IOException {
        return encodeCiphertext(normalizeCiphertext(data, from, STANDARD), to);
    }

    private static DSAEncoding encoding(SM2SignatureFormat format) {
        Checks.required(format, "signature format");
        return format == SM2SignatureFormat.DER ? StandardDSAEncoding.INSTANCE : PlainDSAEncoding.INSTANCE;
    }

    private static void userId(byte[] userId) {
        Checks.required(userId, "user ID");
        if (userId.length > 8191) throw new IllegalArgumentException("SM2 user ID must contain at most 8191 bytes");
    }

    private static SM2Signer signer(SM2SignatureFormat format, boolean prehashed) {
        if (!prehashed) return new SM2Signer(encoding(format));
        // The input is already e, e.g. SM3(ZA || message). Do not hash or add ZA again.
        return new SM2Signer(encoding(format), new NullDigest()) {
            @Override protected byte[] getZ(byte[] ignored) { return new byte[0]; }
        };
    }

    public static byte[] sign(byte[] userId, byte[] key, byte[] message, SM2SignatureFormat format, boolean prehashed) throws IOException {
        userId(userId);
        Checks.required(message, "message");
        if (prehashed) Checks.length(message, 32, "precomputed SM2 digest");
        SM2Signer signer = signer(format, prehashed);
        signer.init(true, new ParametersWithID(new ParametersWithRandom(privateKey(key, STANDARD, true), RANDOM), userId));
        signer.update(message, 0, message.length);
        try { return signer.generateSignature(); }
        catch (CryptoException e) { throw new IOException("SM2 signing failed", e); }
    }

    private static boolean verify(byte[] userId, byte[] key, byte[] message, byte[] signature,
                                  SM2SignatureFormat format, boolean prehashed, ECDomainParameters domain) {
        userId(userId);
        Checks.required(message, "message");
        if (prehashed) Checks.length(message, 32, "precomputed SM2 digest");
        ECPublicKeyParameters publicKey = publicKey(key, domain);
        DSAEncoding encoding = encoding(format);
        if (signature == null || signature.length == 0 || signature.length > 72) return false;
        try {
            BigInteger[] rs = encoding.decode(domain.getN(), signature);
            if (rs[0].signum() <= 0 || rs[1].signum() <= 0) return false;
            SM2Signer signer = signer(format, prehashed);
            signer.init(false, new ParametersWithID(publicKey, userId));
            signer.update(message, 0, message.length);
            return signer.verifySignature(signature);
        } catch (IOException | RuntimeException e) { return false; }
    }

    public static boolean verify(byte[] userId, byte[] key, byte[] message, byte[] signature,
                                 SM2SignatureFormat format, boolean prehashed) {
        return verify(userId, key, message, signature, format, prehashed, STANDARD);
    }

    public static boolean verifyLegacy(byte[] userId, byte[] key, byte[] message, byte[] signature) {
        return verify(userId, key, message, signature, SM2SignatureFormat.DER, false, LEGACY);
    }

    public static byte[] convertSignature(byte[] data, SM2SignatureFormat from, SM2SignatureFormat to) throws IOException {
        Checks.required(data, "signature");
        if (data.length == 0 || data.length > 72) throw new IOException("Invalid SM2 signature length");
        try {
            BigInteger[] rs = encoding(from).decode(STANDARD.getN(), data);
            if (rs[0].signum() <= 0 || rs[1].signum() <= 0) throw new IOException("Invalid SM2 signature range");
            return encoding(to).encode(STANDARD.getN(), rs[0], rs[1]);
        } catch (IllegalArgumentException e) { throw new IOException("Invalid SM2 signature", e); }
    }

    public static byte[] signatureDigest(byte[] id, byte[] rawPublicKey, byte[] message) {
        userId(id);
        Checks.required(message, "message");
        ECPoint q = publicKey(rawPublicKey, STANDARD).getQ().normalize();
        SM3Digest digest = new SM3Digest();
        digest.update((byte) ((id.length * 8) >>> 8));
        digest.update((byte) (id.length * 8));
        digest.update(id, 0, id.length);
        BigInteger[] fields = {STANDARD.getCurve().getA().toBigInteger(), STANDARD.getCurve().getB().toBigInteger(),
            STANDARD.getG().normalize().getAffineXCoord().toBigInteger(), STANDARD.getG().normalize().getAffineYCoord().toBigInteger(),
            q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger()};
        for (BigInteger field : fields) {
            byte[] bytes = BigIntegers.asUnsignedByteArray(32, field);
            digest.update(bytes, 0, bytes.length);
        }
        byte[] z = new byte[32]; digest.doFinal(z, 0);
        digest.update(z, 0, z.length); digest.update(message, 0, message.length);
        byte[] result = new byte[32]; digest.doFinal(result, 0);
        return result;
    }

    private static AlgorithmIdentifier keyAlgorithm() {
        return new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, GMObjectIdentifiers.sm2p256v1);
    }

    private static void checkAlgorithm(AlgorithmIdentifier algorithm) throws IOException {
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm.getAlgorithm())
            || !GMObjectIdentifiers.sm2p256v1.equals(algorithm.getParameters())) {
            throw new IOException("Expected an EC key with named curve sm2p256v1");
        }
    }

    public static byte[] exportPublicKey(byte[] raw) throws IOException {
        return new SubjectPublicKeyInfo(keyAlgorithm(), publicKey(raw, STANDARD).getQ().getEncoded(false)).getEncoded(ASN1Encoding.DER);
    }

    public static byte[] importPublicKey(byte[] der) throws IOException {
        if (Checks.required(der, "SPKI").length > 1024) throw new IOException("SPKI is too large");
        try {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(sequence(der));
            checkAlgorithm(info.getAlgorithm());
            if (info.getPublicKeyData().getPadBits() != 0) throw new IOException("Invalid public key bit string");
            return publicKey(info.getPublicKeyData().getOctets(), STANDARD).getQ().getEncoded(false);
        } catch (RuntimeException e) { throw new IOException("Invalid SM2 public key", e); }
    }

    public static byte[] exportPrivateKey(byte[] raw) throws IOException {
        ECPrivateKeyParameters key = privateKey(raw, STANDARD, false);
        ECPrivateKey sec1 = new ECPrivateKey(256, key.getD(), new DERBitString(derivePublicKey(raw)), GMObjectIdentifiers.sm2p256v1);
        return new PrivateKeyInfo(keyAlgorithm(), sec1).getEncoded(ASN1Encoding.DER);
    }

    public static byte[] importPrivateKey(byte[] der) throws IOException {
        if (Checks.required(der, "PKCS8").length > 16384) throw new IOException("PKCS8 is too large");
        try {
            PrivateKeyInfo info = PrivateKeyInfo.getInstance(sequence(der));
            checkAlgorithm(info.getPrivateKeyAlgorithm());
            ASN1Sequence inner = sequence(info.getPrivateKey().getOctets());
            if (inner.size() < 2 || inner.size() > 4 || !ASN1Integer.getInstance(inner.getObjectAt(0)).hasValue(1)
                || !(inner.getObjectAt(1) instanceof ASN1OctetString)) throw new IOException("Invalid SEC1 private key");
            byte[] scalar = ((ASN1OctetString) inner.getObjectAt(1)).getOctets();
            if (scalar.length < 1 || scalar.length > 32) throw new IOException("Invalid private scalar length");
            byte[] raw = BigIntegers.asUnsignedByteArray(32, new BigInteger(1, scalar));
            privateKey(raw, STANDARD, false);
            ECPrivateKey sec1 = ECPrivateKey.getInstance(inner);
            int previous = -1;
            for (int i = 2; i < inner.size(); i++) {
                ASN1TaggedObject tag = ASN1TaggedObject.getInstance(inner.getObjectAt(i));
                if (tag.getTagClass() != BERTags.CONTEXT_SPECIFIC || tag.getTagNo() <= previous
                    || tag.getTagNo() > 1 || !tag.isExplicit()) throw new IOException("Invalid SEC1 optional fields");
                previous = tag.getTagNo();
            }
            if (sec1.getParametersObject() != null && !GMObjectIdentifiers.sm2p256v1.equals(sec1.getParametersObject())) {
                throw new IOException("Conflicting private key curve");
            }
            checkMatchingPublicKey(raw, sec1.getPublicKey());
            checkMatchingPublicKey(raw, info.getPublicKeyData());
            return raw;
        } catch (RuntimeException e) { throw new IOException("Invalid SM2 private key", e); }
    }

    private static void checkMatchingPublicKey(byte[] privateKey, ASN1BitString embedded) throws IOException {
        if (embedded == null) return;
        if (embedded.getPadBits() != 0 || !Arrays.equals(derivePublicKey(privateKey), uncompressPublicKey(embedded.getOctets()))) {
            throw new IOException("Embedded public key does not match private key");
        }
    }
}
