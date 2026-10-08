import com.heshidai.security.cipher.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.bouncycastle.asn1.*;

/** Local synthetic fixtures only; never print recovered keys or application data. */
public class LegacyProbe {
    private static final PrintStream REPORT = System.out;
    private static final byte[] ID = "review@example.test".getBytes(StandardCharsets.UTF_8);
    private static void result(String name, Object value) { REPORT.println(name + "=" + value); }
    private static byte[] digest(byte[] msg) {
        SM3Digest d = new SM3Digest(); d.update(msg, 0, msg.length);
        byte[] out = new byte[32]; d.doFinal(out, 0); return out;
    }
    private static byte[] encode(ASN1EncodableVector v) throws Exception {
        return new DERSequence(v).getDEREncoded();
    }
    private static ASN1Sequence parse(byte[] value) throws Exception {
        return (ASN1Sequence) new ASN1InputStream(value).readObject();
    }
    private static byte[] mutateCiphertext(byte[] ct, int index) throws Exception {
        ASN1Sequence seq = parse(ct); ASN1EncodableVector v = new ASN1EncodableVector();
        for (int i = 0; i < 4; i++) {
            if (i == index) {
                byte[] changed = ((DEROctetString) seq.getObjectAt(i)).getOctets().clone();
                changed[0] ^= 1; v.add(new DEROctetString(changed));
            } else v.add(seq.getObjectAt(i));
        }
        return encode(v);
    }
    private static byte[] sm4(byte[] key, byte[] input, boolean encrypt, boolean padding) throws Exception {
        SM4 impl = new SM4(); SM4_Context ctx = new SM4_Context(); ctx.isPadding = padding;
        if (encrypt) impl.sm4_setkey_enc(ctx, key); else impl.sm4_setkey_dec(ctx, key);
        return impl.sm4_crypt_ecb(ctx, input);
    }
    public static void main(String[] args) throws Exception {
        ByteArrayOutputStream capture = new ByteArrayOutputStream();
        System.setOut(new PrintStream(capture, true, "UTF-8"));
        SM2 curve = SM2.Instance();
        BigInteger d = new BigInteger("123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234", 16);
        byte[] priv = Util.byteConvert32Bytes(d);
        byte[] pub = curve.ecc_point_g.multiply(d).getEncoded();
        byte[] msg = "synthetic review message".getBytes(StandardCharsets.UTF_8);
        byte[] sig = SM2Utils.sign(ID, priv, msg);
        ASN1Sequence seq = parse(sig);
        BigInteger r = ((DERInteger) seq.getObjectAt(0)).getValue();
        BigInteger s = ((DERInteger) seq.getObjectAt(1)).getValue();
        BigInteger k = new BigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16);
        BigInteger recovered = k.subtract(s).multiply(s.add(r).modInverse(curve.ecc_n)).mod(curve.ecc_n);
        result("sm2_private_key_recovered_from_one_signature", recovered.equals(d));
        result("sm2_private_key_written_to_stdout", capture.toString("UTF-8").contains("userD: " + d.toString(16)));
        result("sm2_same_message_same_signature", Arrays.equals(sig, SM2Utils.sign(ID, priv, msg)));
        result("sm2_original_signature_verifies", SM2Utils.verifySign(ID, pub, msg, sig));
        ASN1EncodableVector invalidSig = new ASN1EncodableVector();
        invalidSig.add(new DERInteger(r)); invalidSig.add(new DERInteger(s.add(curve.ecc_n)));
        result("sm2_signature_with_s_plus_n_accepted", SM2Utils.verifySign(ID, pub, msg, encode(invalidSig)));
        BigInteger highD = new BigInteger("8000000000000000000000000000000000000000000000000000000000000001", 16);
        byte[] highPub = curve.ecc_point_g.multiply(highD).getEncoded();
        try {
            result("sm2_valid_high_bit_private_key_verifies", SM2Utils.verifySign(ID, highPub, msg,
                SM2Utils.sign(ID, Util.byteConvert32Bytes(highD), msg)));
        } catch (IllegalArgumentException e) {
            result("sm2_valid_high_bit_private_key_verifies", false);
            result("sm2_high_bit_private_key_error", e.getMessage());
        }
        byte[] ct = SM2Utils.encrypt(pub, msg);
        result("sm2_original_ciphertext_roundtrip", Arrays.equals(msg, SM2Utils.decrypt(priv, ct)));
        result("sm2_changed_c3_accepted", Arrays.equals(msg, SM2Utils.decrypt(priv, mutateCiphertext(ct, 2))));
        byte[] changed = SM2Utils.decrypt(priv, mutateCiphertext(ct, 3));
        byte[] expected = msg.clone(); expected[0] ^= 1;
        result("sm2_changed_c2_returns_predictably_changed_plaintext", Arrays.equals(expected, changed));
        result("sm2_empty_plaintext_returns_null", SM2Utils.encrypt(pub, new byte[0]) == null);

        byte[] abc = "abc".getBytes(StandardCharsets.US_ASCII);
        result("sm3_abc", Util.byteToHex(digest(abc)).toLowerCase(Locale.ROOT));
        int[] lengths = {0,1,55,56,63,64,65,127,128,129,1024,65536};
        for (int len : lengths) {
            byte[] data = new byte[len]; for (int i = 0; i < len; i++) data[i] = (byte) (i * 31 + 7);
            result("sm3_len_" + len, Util.byteToHex(digest(data)).toLowerCase(Locale.ROOT));
        }
        byte[] streamData = new byte[1024]; new Random(42).nextBytes(streamData);
        boolean chunksMatch = true;
        for (int chunk : new int[] {1,3,63,64,65,1024}) {
            SM3Digest streamDigest = new SM3Digest();
            for (int pos = 0; pos < streamData.length; pos += chunk)
                streamDigest.update(streamData, pos, Math.min(chunk, streamData.length - pos));
            byte[] value = new byte[32]; streamDigest.doFinal(value, 0);
            chunksMatch &= Arrays.equals(value, digest(streamData));
        }
        result("sm3_six_chunk_sizes_match_one_shot", chunksMatch);
        SM3Digest offset = new SM3Digest(); offset.update(abc, 0, abc.length);
        byte[] out = new byte[48]; Arrays.fill(out, (byte) 0x55); offset.doFinal(out, 8);
        result("sm3_out_offset_honored", Arrays.equals(digest(abc), Arrays.copyOfRange(out, 8, 40)) && out[0] == 0x55);
        byte[] prefix = new byte[100]; Arrays.fill(prefix, (byte) 3);
        SM3Digest original = new SM3Digest(); original.update(prefix, 0, prefix.length);
        SM3Digest copy = new SM3Digest(original);
        byte[] a = new byte[32], b = new byte[32]; original.doFinal(a, 0); copy.doFinal(b, 0);
        result("sm3_copy_after_processed_block_matches", Arrays.equals(a, b));
        SM3Digest reused = new SM3Digest(); reused.update(abc, 0, abc.length); reused.doFinal(new byte[32], 0);
        reused.update(abc, 0, abc.length); reused.doFinal(a, 0);
        result("sm3_doFinal_resets_for_reuse", Arrays.equals(a, digest(abc)));
        byte[] pad = SM3.padding(new byte[0], 4194304);
        result("sm3_256MiB_length_field", Util.byteToHex(Arrays.copyOfRange(pad, pad.length - 8, pad.length)));

        byte[] key = Util.hexToByte("0123456789abcdeffedcba9876543210");
        result("sm4_standard_vector", Util.byteToHex(sm4(key, key, true, false)).toLowerCase(Locale.ROOT));
        Random rng = new Random(42);
        java.security.MessageDigest aggregate = java.security.MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 64; i++) {
            byte[] randomKey = new byte[16], block = new byte[16]; rng.nextBytes(randomKey); rng.nextBytes(block);
            aggregate.update(sm4(randomKey, block, true, false));
        }
        result("sm4_64_blocks_sha256", Util.byteToHex(aggregate.digest()).toLowerCase(Locale.ROOT));
        byte[] badPad = new byte[16]; Arrays.fill(badPad, (byte) 0x41); badPad[14] = 1; badPad[15] = 2;
        result("sm4_invalid_padding_accepted", sm4(key, sm4(key, badPad, true, false), false, true).length == 14);
        badPad[15] = 0;
        result("sm4_zero_padding_accepted", sm4(key, sm4(key, badPad, true, false), false, true).length == 16);
        result("sm4_truncated_block_accepted", sm4(key, new byte[15], false, false).length == 16);
        SM4 impl = new SM4(); SM4_Context ctx = new SM4_Context(); ctx.isPadding = false;
        impl.sm4_setkey_enc(ctx, key); byte[] iv = new byte[16];
        impl.sm4_crypt_cbc(ctx, iv, key);
        result("sm4_cbc_mutates_caller_iv", !Arrays.equals(iv, new byte[16]));
        SM4Utils strings = new SM4Utils(); strings.setSecretKey("0123456789abcdef");
        String unicode = "hello\ud83d\ude42";
        result("sm4_unicode_roundtrip", unicode.equals(strings.decryptData_ECB(strings.encryptData_ECB(unicode))));
        result("hex_odd_length_silently_truncated", Util.hexStringToBytes("ABC").length == 1);
        result("hex_non_hex_accepted", Util.hexStringToBytes("GG").length == 1);
        System.setOut(REPORT);
    }
}
