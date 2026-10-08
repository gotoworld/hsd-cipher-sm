# 国密互通指南

先确定字节和协议，再选择格式。SM2 名称相同并不能保证曲线、密钥文件、密文顺序、签名编码与 userId 相同。

## 已提供的独立互通测试

执行 `mvn -B clean verify -Dopenssl.integration=true`，要求 PATH 中 OpenSSL 3.x 可用。启用后工具缺失、超时或任何互通失败都会使构建失败。测试使用临时生成的非生产密钥和二进制文件。

| 方向 | 实际验证 |
| --- | --- |
| Java 加密 → OpenSSL 解密 | 标准曲线、DER 密文，逐字节明文相同 |
| OpenSSL 加密 → Java 解密 | C3 验证后逐字节相同 |
| Java 签名 → OpenSSL 验签 | SM3、相同 distinguishing ID、DER 签名 |
| OpenSSL 签名 → Java 验签 | 同一消息原始字节与 ID |
| OpenSSL 生成密钥 → Java 导入 | PKCS#8/SPKI PEM，私钥推导公钥相同，再交换密文 |
| SM3、HMAC-SM3、SM4-CBC | 与 OpenSSL 计算结果比较 |

测试源码为 `OpenSSLInteropTest.java`。SM4-GCM 通过 RFC 8998 Appendix A.1 固定向量验证；OpenSSL `enc` 命令不承担此模式的互通测试。当前没有声明已验证所有 Go、JavaScript 库或密码机。

## OpenSSL 对接命令

以下文件可由应用使用 SM2Utils 的 PEM、DER 输出方法生成。`message.bin` 是原始消息字节；命令中的 ID 必须在两端一致。

```sh
openssl pkeyutl -decrypt -inkey private.pem -in java.ct -out plaintext.bin
openssl pkeyutl -encrypt -pubin -inkey public.pem -in message.bin -out openssl.ct
openssl dgst -sm3 -sign private.pem -sigopt distid:1234567812345678 -out openssl.sig message.bin
openssl dgst -sm3 -verify public.pem -sigopt distid:1234567812345678 -signature java.sig message.bin
```

SM2Utils 的默认 DER 密文适合此流程。需要 raw 时使用枚举与 convertCiphertext 明确转换。不要把 PEM 文本作为 raw 公钥字节，或把 ASCII Hex 当作已经解码的二进制。

## 跨语言问题排查

| 顺序 | 核对项 | 常见差异 |
| --- | --- | --- |
| 1 | 曲线 | sm2p256v1 与旧 8542D69E 测试曲线不能互通 |
| 2 | 密钥 | raw SEC1 公钥、SPKI、公钥 PEM；raw 私钥、PKCS#8、私钥 PEM |
| 3 | 消息字节 | UTF-8/GBK、换行、JSON 序列化、数字格式、二进制中的 00 |
| 4 | 密文 | DER 与 raw；C1C3C2 与 C1C2C3 |
| 5 | C1 | 本库 raw 必须包含 04；有的 JS 接口会自行补充 |
| 6 | 签名 | DER 与固定 64 字节 r||s；正整数的 DER 00 符号保护 |
| 7 | userId | 两端精确字节一致；常见默认值不是所有协议的通用值 |
| 8 | 摘要边界 | message、ZA、SM3(ZA||message) 与硬件接收 e 的区别 |

转换签名时使用 convertSignature，避免把可变长度 DER INTEGER 当成固定宽度 r/s。转换密文只处理格式，不认证数据；应用只有在 decrypt 成功后才能信任明文。

硬件对接需确认摘要究竟由哪一端计算。`signatureDigest` 与 `signPrecomputedDigest/verifyPrecomputedDigest` 为明确的 e 边界提供支持；不建议靠“关闭 ZA”的布尔开关猜测设备协议。

## SM4 本地封装格式

`SM4.seal/open` 的版本 1 二进制结构为：4 字节 ASCII `HSM4`，1 字节版本 01，1 字节算法 01（SM4-GCM），2 字节大端 keyId 长度（1..255），UTF-8 keyId，12 字节 nonce，剩余密文与末尾 16 字节 tag。AAD 为 nonce 之前的完整 header 拼接调用方提供的外部 AAD。

外部 AAD 不存入封装，解密方必须获得相同字节。keyId 的 UTF-8 解码严格，未知版本和算法被拒绝。keyId 可用于查找密钥，但查找阶段它仍是不可信输入，不应决定租户权限或绕过应用授权。业务中的 keyId→密钥映射及数据访问控制由应用负责。

此格式是明确版本化的应用工具格式，不宣称兼容第三方协议。对已有设备使用 encryptGcm/decryptGcm 或显式 CBC 接口，按对方文档处理 nonce、tag、AAD 与报文。
