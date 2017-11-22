package com.heshidai.security.cipher;

import org.bouncycastle.asn1.*;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;


public class SM2Test {

    @Test
    public void testSM2() throws Exception {
        String plainText = "message digest";
        byte[] sourceData = plainText.getBytes();

        // 国密规范测试私钥
        String prik = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
        String prikS = new String(Base64.encode(Util.hexToByte(prik)));
        System.out.println("prikS: " + prikS);
        System.out.println("");

        // 国密规范测试用户ID
        String userId = "ALICE123@YAHOO.COM";

        System.out.println("ID: " + Util.getHexString(userId.getBytes()));
        System.out.println("");

        System.out.println("签名: ");
        byte[] c = SM2Utils.sign(userId.getBytes(), Base64.decode(prikS.getBytes()), sourceData);
        System.out.println("sign: " + Util.getHexString(c));
        System.out.println("");

        // 国密规范测试公钥
        String pubk = "040AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
        String pubkS = new String(Base64.encode(Util.hexToByte(pubk)));
        System.out.println("pubkS: " + pubkS);
        System.out.println("");


        System.out.println("验签: ");
        boolean vs = SM2Utils.verifySign(userId.getBytes(), Base64.decode(pubkS.getBytes()), sourceData, c);
        System.out.println("验签结果: " + vs);
        System.out.println("");

        System.out.println("加密: ");
        byte[] cipherText = SM2Utils.encrypt(Base64.decode(pubkS.getBytes()), sourceData);
        System.out.println(new String(Base64.encode(cipherText)));
        System.out.println("");

        System.out.println("解密: ");
        plainText = new String(SM2Utils.decrypt(Base64.decode(prikS.getBytes()), cipherText));
        System.out.println(plainText);
    }




}
