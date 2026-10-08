import java.nio.charset.StandardCharsets;
import java.util.*;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.asn1.gm.GMNamedCurves;
public class ReferenceProbe {
    public static void main(String[] args) throws Exception {
        System.out.println("reference_provider=" + new org.bouncycastle.jce.provider.BouncyCastleProvider().getVersionStr());
        int[] lengths = {0,1,55,56,63,64,65,127,128,129,1024,65536};
        for (int len : lengths) {
            byte[] data = new byte[len]; for (int i = 0; i < len; i++) data[i] = (byte) (i * 31 + 7);
            SM3Digest digest = new SM3Digest(); digest.update(data, 0, data.length);
            byte[] out = new byte[32]; digest.doFinal(out, 0);
            System.out.println("sm3_len_" + len + "=" + Hex.toHexString(out));
        }
        SM4Engine sm4 = new SM4Engine(); byte[] key = Hex.decode("0123456789abcdeffedcba9876543210");
        sm4.init(true, new KeyParameter(key)); byte[] out = new byte[16]; sm4.processBlock(key, 0, out, 0);
        System.out.println("sm4_standard_vector=" + Hex.toHexString(out));
        Random rng = new Random(42);
        java.security.MessageDigest aggregate = java.security.MessageDigest.getInstance("SHA-256");
        for (int i = 0; i < 64; i++) {
            byte[] randomKey = new byte[16], block = new byte[16]; rng.nextBytes(randomKey); rng.nextBytes(block);
            sm4.init(true, new KeyParameter(randomKey)); sm4.processBlock(block, 0, out, 0); aggregate.update(out);
        }
        System.out.println("sm4_64_blocks_sha256=" + Hex.toHexString(aggregate.digest()));
        System.out.println("standard_sm2_curve_p=" + GMNamedCurves.getByName("sm2p256v1").getCurve().getField().getCharacteristic().toString(16));
    }
}
