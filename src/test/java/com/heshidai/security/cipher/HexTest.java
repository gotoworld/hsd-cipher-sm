package com.heshidai.security.cipher;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HexTest {
    @Test void aliasesUseStrictAsciiHexAndFixedWidthUnsignedIntegers() {
        assertArrayEquals(new byte[0], Hex.decode(""));
        assertEquals("00abcdef", Hex.encode(Hex.decode("00AbCdEf")));
        assertArrayEquals(Hex.decode("ABCDEF"), Util.hexStringToBytes("ABCDEF"));
        assertArrayEquals(Hex.decode("ABCDEF"), Util.decodeHex("ABCDEF".toCharArray()));
        assertArrayEquals(Hex.decode("ABCDEF"), Util.hexToByte("ABCDEF"));
        for (String bad : new String[] {"ABC", "GG", "00 11", "ＡＡ", "１２"}) {
            assertThrows(IllegalArgumentException.class, () -> Hex.decode(bad));
            assertThrows(IllegalArgumentException.class, () -> Util.hexStringToBytes(bad));
            assertThrows(IllegalArgumentException.class, () -> Util.hexToByte(bad));
            assertThrows(IllegalArgumentException.class, () -> Util.decodeHex(bad.toCharArray()));
        }
        assertThrows(IllegalArgumentException.class, () -> Hex.decode(null));
        assertThrows(IllegalArgumentException.class, () -> Util.byteConvert32Bytes(BigInteger.valueOf(-1)));
        assertThrows(IllegalArgumentException.class, () -> Util.byteConvert32Bytes(BigInteger.ONE.shiftLeft(256)));
        assertEquals(BigInteger.ONE.shiftLeft(255), Util.byteConvertInteger(Util.byteConvert32Bytes(BigInteger.ONE.shiftLeft(255))));
    }
}
