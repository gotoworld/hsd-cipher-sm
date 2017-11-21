package com.heshidai.security.cipher;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class SM2Result
{
	public SM2Result() {
	}

	// 签名/验签
	public BigInteger r;
	public BigInteger s;
	public BigInteger R;

	// 密钥交换
	public byte[] sa;
	public byte[] sb;
	public byte[] s1;
	public byte[] s2;

	public ECPoint keyra;
	public ECPoint keyrb;
}
