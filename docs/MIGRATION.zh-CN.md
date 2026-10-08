# 从历史版本迁移到 2.0

2.0 改为维护中的 BC 实现与标准曲线。原版本的固定签名 nonce 和私钥日志属于已确认的泄露路径；曾用于真实签名的密钥需要更换，相关用途复用同一私钥时应一并检查。历史验签通过只能说明数学一致性，不能恢复旧签名真实性或密钥保密性。

## 不兼容变更

| 旧行为 | 2.0 行为 | 迁移方式 |
| --- | --- | --- |
| SM2Utils 默认历史测试曲线 | 默认 sm2p256v1 | 新生成标准曲线密钥；旧数据显式读取 |
| SM2 密钥接受任意字节长度 | 标准 raw 私钥恰好 32 字节、无符号 | 用 PKCS#8 导入或按正确标量补足 32 字节，不截断 |
| SM4Utils 默认 GBK，key/IV 使用平台编码 | 默认 UTF-8，严格文本转换 | 旧数据选择明确的 GBK；必要时设置原 keyCharset |
| 错误参数返回 null 或打印异常 | 失败使用明确异常，验签拒绝坏签名 | 调整调用方错误处理；远端响应不要回显底层原因 |
| SM3Digest 完成后留下旧状态 | doFinal 后 reset | 依赖旧复用错误的代码需改正 |
| 可直接调用 Cipher 解密并提前获得明文 | 该 API 已删除 | 使用完成 C3 验证后才返回的 SM2Utils.decrypt |
| SM2、SM2Result、SM4_Context、SM4 底层轮函数和 SM3 CF/padding | 不再作为生产 API | 密钥生成用 generateKeyPair；分组运算用 encryptBlock/decryptBlock；历史源码可查 Git |
| 多套宽松 Hex | 全部相关别名改为严格 ASCII Hex | 修正奇数长度、非法字符和隐含空值，不再悄悄截断 |

保留常用 SM2Utils 方法签名、SM3Digest 的更新/复制/完成接口和 SM4Utils 的 ECB/CBC 方法。曲线、字符集与错误语义变化需要按主版本升级处理。internal 包不属于稳定公开接口。

## 读取旧 SM2 密文

旧格式是测试曲线下的 DER `SEQUENCE(INTEGER x, INTEGER y, OCTET STRING C3, OCTET STRING C2)`。如果能够确认记录来自这个版本：

```java
byte[] oldPlaintext = com.heshidai.security.cipher.legacy.LegacySM2.decrypt(oldPrivateKey, oldDerCiphertext);
SM2KeyPair newKeys = SM2Utils.generateKeyPair(); // 实际迁移应由应用统一生成、保存和轮换密钥
byte[] newCiphertext = SM2Utils.encrypt(newKeys.getPublicKey(), oldPlaintext);
```

旧私钥读取接受 1 至 32 字节无符号表示，或恰好 33 字节且首字节为 00 的 BigInteger 表示；最终仍检查非零及曲线范围。新 raw 接口不采用这些宽松长度。

兼容读取依然要求 canonical DER、有效曲线点与正确 C3。不提供“忽略完整性失败”开关。原始数据若已损坏或被篡改，应进入失败清单；不要通过放宽校验强行迁移。

旧曲线公钥、密文和签名不能只换 OID、调整字段顺序或重新 Base64 就变成标准曲线数据。需要旧私钥解密后重加密，或由可信业务源重新签名；无法恢复的历史签名不能包装成新签名。

## 读取旧 SM4 GBK 数据

```java
SM4Utils old = new SM4Utils();
old.setSecretKey(oldKeyText);
old.setIv(oldIvText);
old.setHexString(false); // 如果历史 key/IV 为 Hex，显式设置 true
old.setCharset(java.nio.charset.Charset.forName("GBK"));
// 只有历史运行环境的 key/IV 本身使用 GBK 编码时才设置；ASCII key/IV 不受影响。
old.setKeyCharset(java.nio.charset.Charset.forName("GBK"));
String text = old.decryptData_CBC(oldBase64Ciphertext);
byte[] migrated = SM4.seal(newDataKey, "new-key-id",
    text.getBytes(java.nio.charset.StandardCharsets.UTF_8), recordAssociatedData);
```

固定 GBK 编码曾把不支持的字符替换为问号，这种数据损失不能通过解密恢复。新封装拒绝无法表示的字符。原 CBC 数据没有消息认证；正确填充不证明来源可信，迁移前还需使用应用已有的来源与业务校验。

## 分批迁移流程

1. 备份原记录，记录已确认的曲线、模式、字符集和格式；不要自动猜测。
2. 应用增加新格式标识和 keyId，先做到显式读旧、新写新。
3. 用来源可信的样本核对迁移，分批执行并保留失败记录。
4. 检查数量、业务字段和新格式往返；日志只保存记录标识与错误分类。
5. 完成消费者升级与备份保留后，停用旧写入和相关密钥。密钥删除由应用运维流程负责。

旧 SM3 对超过 256 MiB 数据的长度计算可能错误，应重新计算摘要并核对可信原文件。结果变化不能直接判为文件损坏。

## 回归样本

`src/test/resources/legacy-v1.properties` 使用原提交和 BC 1.46 生成，包含明确的非生产测试密钥、原密文/签名和 GBK ECB/CBC 样本。测试要求修复后的兼容读取成功，篡改时失败。历史缺陷探针在 `docs/maintenance-review`；它们提取旧提交运行，不用于证明当前版本安全。
