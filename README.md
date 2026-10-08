# HSD CIPHER SM

Java 国密接入与互通工具库，提供标准曲线 SM2、SM3、HMAC-SM3、SM4-GCM，以及显式的历史数据读取。密码运算由 Bouncy Castle 实现，不修改 JVM 全局 provider 配置。

当前工作版本：**2.0.0-SNAPSHOT**。这是包含不兼容变更的开发版本，尚未发布到 Maven Central。历史 `1.0-SNAPSHOT` 签名存在固定随机数和私钥输出问题，解密缺少 C3 校验。曾在真实业务使用旧签名路径的用户需要更换相关密钥；升级代码无法恢复旧密钥保密性。参见[迁移说明](docs/MIGRATION.zh-CN.md)和[安全说明](SECURITY.md)。

## 构建与接入

要求 JDK 8 或以上、Maven 3.6.3 或以上。CI 配置覆盖 JDK 8、17、21、25；具体本地验证结果见[验证记录](docs/VERIFICATION.zh-CN.md)。

```sh
mvn -B clean install
bash examples/run.sh
```

安装到本地 Maven 仓库后，消费者可以使用以下坐标。它不代表该开发版本已经公开发布。

```xml
<dependency>
    <groupId>com.heshidai.security</groupId>
    <artifactId>hsd-cipher-sm</artifactId>
    <version>2.0.0-SNAPSHOT</version>
</dependency>
```

依赖 `org.bouncycastle:bcprov-jdk18on:1.86`。应用类路径中应只保留一个 BC 系列；不要同时引入旧的 `bcprov-jdk16`、`bcprov-jdk15on` 等包含同名类的 jar。需要 PKIX 时，保持 `bcpkix`、`bcutil` 与 provider 的系列和版本一致。可用 `mvn dependency:tree -Dincludes=org.bouncycastle` 排查；依赖升级需重新运行互通与迁移测试。

## 快速开始

以下代码使用 `com.heshidai.security.cipher.*`，示例密钥均临时生成。完整可运行代码见 [QuickStart.java](examples/src/main/java/com/heshidai/security/cipher/examples/QuickStart.java)。

```java
byte[] message = "Hello 国密🙂".getBytes(java.nio.charset.StandardCharsets.UTF_8);
SM2KeyPair keys = SM2Utils.generateKeyPair();

byte[] ciphertext = SM2Utils.encrypt(keys.getPublicKey(), message);
byte[] plaintext = SM2Utils.decrypt(keys.getPrivateKey(), ciphertext);

byte[] userId = SM2Utils.defaultUserId(); // 必须与对端协议一致
byte[] signature = SM2Utils.sign(userId, keys.getPrivateKey(), message);
boolean valid = SM2Utils.verifySign(userId, keys.getPublicKey(), message, signature);

byte[] hash = SM3.digest(message);
byte[] dataKey = SM4.generateKey();
byte[] aad = "record-id-123".getBytes(java.nio.charset.StandardCharsets.UTF_8);
byte[] sealed = SM4.seal(dataKey, "data-key-2026", message, aad);
byte[] opened = SM4.open(dataKey, sealed, aad);
```

`SM4.seal/open` 使用本项目的版本化数据封装，包含认证的 keyId、随机 nonce 与 tag。它不是 TLS 报文或通用行业文件格式。keyId 不包含密钥；密钥存储和轮换由应用负责。`SM4.envelopeKeyId` 只提供未认证的路由提示，必须在 `open` 成功后才能信任。

大文件摘要直接使用 `SM3.digest(InputStream)`，不会关闭调用方的流。带密钥认证使用独立随机密钥调用 `SM3.hmac(key, message)` 或 `verifyHmac`；普通 SM3 摘要不能代替 MAC。

## 格式与接口契约

| 内容 | 默认或支持的形式 |
| --- | --- |
| SM2 曲线 | 固定 `sm2p256v1`，不自动猜测旧测试曲线 |
| 原始私钥 | 恰好 32 字节无符号标量；签名范围 1 至 n−2，解密范围 1 至 n−1 |
| 原始公钥 | 65 字节 `04 || X || Y` 或 33 字节压缩 SEC1 点，拒绝无穷远及 hybrid 编码 |
| SM2 密文 | 默认 DER `SEQUENCE(x,y,C3,C2)`；可显式选择 `RAW_C1C3C2` 或 `RAW_C1C2C3` |
| raw 密文 C1 | 恰好 65 字节，包含 `04`；与部分 JS 库交换时注意前缀约定 |
| SM2 签名 | 默认 canonical DER `(r,s)`；可选 `PLAIN_RS`，即 32 字节 r 与 32 字节 s |
| SM2 userId | 显式非 null、最多 8191 字节；常见值 `1234567812345678` 仅是便捷选项 |
| 密钥文件 | 命名 SM2 曲线的 SPKI 公钥、PKCS#8 私钥；DER 或单对象 PEM |
| 文本 | 密码接口接收 byte[]；SM4Utils 文本默认 UTF-8，GBK 必须显式指定 |
| SM4-GCM | 16 字节密钥、12 字节 nonce、16 字节 tag、调用方明确提供 AAD |
| SM4 ECB/CBC | 显式选择 `PKCS7` 或 `NONE`，不提供消息认证，仅用于明确的对接协议 |

用 `convertCiphertext`、`convertSignature` 转换同一标准曲线下的格式；格式转换不验证密文真实性，也不能跨曲线转换密钥或数据。密钥文件接口包括 `publicKeyToSpki/fromSpki`、`privateKeyToPkcs8/fromPkcs8` 以及对应 PEM 方法。

`signatureDigest(userId, publicKey, message)` 计算 `e = SM3(ZA || message)`。高级接口 `signPrecomputedDigest` 和 `verifyPrecomputedDigest` 接收恰好 32 字节的 e，不再加入 ZA 或计算摘要，供明确的硬件协议使用。不要把原消息、ZA 或仅对消息计算的 SM3 与 e 混用。

SM2 加密拒绝空明文；签名和 SM3 支持空消息。非法参数抛出 `IllegalArgumentException`；错误密文、校验失败或错误解密密钥抛出 `CipherException`（IOException 的子类），不返回部分明文。验签对无效签名返回 false；无效公钥或 userId 属于参数错误。格式导入失败使用 IOException。SM4Utils 因保留旧方法签名，将解密失败转为 IllegalArgumentException，不再吞异常返回 null。

## 互通与测试

```sh
mvn -B clean verify
# PATH 中需要 OpenSSL 3.x；启用后，缺少工具或互通失败会导致测试失败。
mvn -B clean verify -Dopenssl.integration=true
```

测试覆盖固定签名向量、SM3 标准向量、SM4 标准分组和百万次迭代向量、RFC 8998 SM4-GCM 向量、格式与解析边界、篡改拒绝、旧曲线/GBK 样本，以及 256 MiB + 1 字节流式摘要。

OpenSSL 测试执行双向 SM2 加解密、双向签名验签、独立生成的密钥导入、SM3/HMAC 和 SM4-CBC 比较。具体命令、格式排查顺序与覆盖边界见[互通指南](docs/INTEROPERABILITY.zh-CN.md)。不能把算法样本通过等同于安全认证或对所有硬件的兼容承诺。

## 迁移与维护

旧曲线读取入口在 `com.heshidai.security.cipher.legacy.LegacySM2`，仅支持 `decrypt` 与 `verifySignature`。旧 GBK 文本通过 `SM4Utils.setCharset(Charset.forName("GBK"))` 显式读取。旧签名生成和未认证的底层 Cipher API 已移除。完整变更见[迁移指南](docs/MIGRATION.zh-CN.md)、[CHANGELOG](CHANGELOG.md)和[原始项目分析](docs/maintenance-review/README.zh-CN.md)。

贡献流程见 [CONTRIBUTING](CONTRIBUTING.md)。公开发布前须完成[发布检查](docs/RELEASING.zh-CN.md)，包括原代码与贡献的权属、许可证和私密安全报告渠道确认。当前未替权利人添加授权声明；许可状态见[许可说明](docs/LICENSING.zh-CN.md)。
