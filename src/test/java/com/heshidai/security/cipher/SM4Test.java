package com.heshidai.security.cipher;

import org.junit.Assert;
import org.junit.Test;

public class SM4Test {

    @Test
    public void testSM4()
    {
        try
        {
            String plainText = "abcd";
    
            SM4Utils sm4 = new SM4Utils();
            sm4.setSecretKey("JeF8U9wHFOMfs2Y8");
            sm4.setHexString(false);
    
            System.out.println("ECB模式");
            String cipherText = sm4.encryptData_ECB(plainText);
            System.out.println("密文: " + cipherText);
            System.out.println("");
    
            String decryptedText = sm4.decryptData_ECB(cipherText);
            System.out.println("明文: " + plainText);
            System.out.println("");
            if (!plainText.equals(decryptedText))
            {
                Assert.assertTrue(false);
            }
    
            System.out.println("CBC模式");
            sm4.setIv("UISwD9fW6cFh9SNS");
            cipherText = sm4.encryptData_CBC(plainText);
            System.out.println("密文: " + cipherText);
            System.out.println("");
    
            decryptedText = sm4.decryptData_CBC(cipherText);
            System.out.println("明文: " + plainText);
            if (!plainText.equals(decryptedText))
            {
                Assert.assertTrue(false);
            }
            
            Assert.assertTrue(true);
        } 
        catch (Exception ex)
        {
            ex.printStackTrace();
            Assert.assertTrue(false);
        }
    }
}
