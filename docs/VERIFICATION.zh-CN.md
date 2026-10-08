# 2.0 修复验证记录

验证日期为 2026 年 10 月 8 日，针对当前 `2.0.0-SNAPSHOT` 工作树。原始基线是 `f1af537ab46215446dd04918179440a9b08b1615`。以下区分实际执行结果、独立审查与尚未执行的环境，不把测试通过称为安全认证。

## 实际执行环境与结果

| 检查 | 环境 | 结果 |
| --- | --- | --- |
| clean verify，开启 OpenSSL 互通 | Oracle JDK 8u461，Maven 3.8.4 | 46 项测试通过，0 失败、0 错误、0 跳过；主包、源码包、Javadoc 包生成成功 |
| clean verify，开启 OpenSSL 互通 | Oracle JDK 17.0.16，Maven 3.8.4 | 46 项测试通过，0 失败、0 错误、0 跳过；三个包生成成功 |
| clean verify，开启 OpenSSL 互通 | Oracle JDK 21.0.8，Maven 3.8.4 | 46 项测试通过，0 失败、0 错误、0 跳过；三个包生成成功 |
| 独立消费者 | 主包安装到临时 Maven 仓库，examples 使用公开 API 与传递依赖 | 编译和 QuickStart 运行成功 |
| 包内容 | 主 jar 中全部 18 个 class | class major version 全部为 52（Java 8）；旧 SM2/Cipher/SM2Result/SM4_Context 类不存在；未内嵌 BC 类 |
| 历史探针 | 从 Git 提取原始提交，BC 1.46 与 1.86 在分离 JVM 中运行 | 22 项历史行为复现，14 项差分输出相同；只证明旧行为，没有把漏洞保留到新代码 |
| 静态配置 | Git diff、XML、YAML 与 shell 语法检查 | 无 whitespace 错误，POM/YAML 可解析，脚本语法通过 |

独立参考实现为本机 OpenSSL 3.6.4。固定生产依赖为 `bcprov-jdk18on:1.86`，测试使用 JUnit Jupiter 5.10.3 和 Surefire 3.2.5。构建使用临时 Maven Central 镜像配置和临时缓存，没有依赖原来的私网 Nexus 发布地址。

## 安全问题的关闭证据

| 原问题 | 新边界与验证 |
| --- | --- |
| 固定签名 nonce 可恢复私钥 | 新签名使用 BC SM2Signer 与 SecureRandom；不存在旧公开低层签名路径。重复签名不同、旧已知 nonce 的恢复公式不再恢复当前私钥，标准向量和 OpenSSL 验签通过 |
| 私钥与消息自动输出 | 捕获有效和无效调用的 stdout/stderr，输出为空；公开 API 不调用历史打印逻辑 |
| 缺少 C3 校验 | 标准及 legacy 解密都通过完整 BC SM2Engine 流程；改变 C1/C2/C3、错密钥或坏结构时不返回明文 |
| 标量、点与编码绕过 | 检查高位 unsigned 私钥、零/越界值、n−1 签名拒绝、s+n、负数/零签名、尾随 DER、BER、错误字段与 C1 hybrid 编码 |
| 摘要 offset/copy/reset/长度错误 | 非零输出偏移与哨兵、跨块状态复制、对象复用、多种分块，以及真实 256 MiB + 1 字节零流；大流结果与独立 OpenSSL 预计算结果一致 |
| SM4 填充与截断输入 | 构造非法填充、0/越界填充和非完整分组，ECB/CBC 拒绝；正常填充与空消息符合声明契约 |
| 文本和 IV 行为 | UTF-8 Unicode 往返、原 GBK 样本、不可表示字符拒绝、调用方 IV 不变 |
| 新认证封装 | RFC 8998 GCM 向量通过；逐字节改变封装、错 AAD、错密钥或 tag 被拒绝 |

随机签名检查仅是回归辅助，不单独证明随机源安全。原问题关闭还依赖实际执行路径改为 BC 的随机签名，并删除可绕过认证的旧低层类。

## 保持合法行为的证据

保留常用工具入口，正常 SM2 加解密、签名验签、压缩公钥、SPKI/PKCS#8 与 PEM 导入导出、空消息签名、SM3 流式更新、SM4 正常模式均有断言。2.0 的标准曲线、UTF-8 与错误语义变化在迁移指南中明确记录。

原实现生成的测试曲线 DER 密文/签名和 GBK ECB/CBC 样本能够通过显式兼容入口读取；兼容入口同样拒绝被篡改内容。旧签名生成没有保留。真实业务数据迁移仍应由使用者以其来源、密钥、字符集和协议配置验证。

## 独立检查

一次独立的只读调查识别了旧 public SM2.sm2Sign 和 Cipher.Decrypt 的旁路，修复范围包含这些入口。实现后进行一次新的只读绕过与回归审查，覆盖当前生产/测试源码、新解析器、legacy 路径、状态处理、封装与迁移契约；审查未发现具体剩余绕过或非预期工作流回归。该审查检查了源码及相关 BC 字节码，没有替代或声称重新执行测试。

## 复验命令与范围

```sh
mvn -B clean verify -Dopenssl.integration=true
mvn -B install
bash examples/run.sh
git diff --check
bash -n examples/run.sh docs/maintenance-review/run-probes.sh
```

本机为三个 JDK 分别设置 JAVA_HOME 执行完整构建。GitHub workflow 已配置 8、17、21、25，但尚未在远端执行；JDK 25 没有在本机验证。其他 OS、所有 Go/JS 库、密码硬件、侧信道、JVM 内存擦除和正式密码认证不在本次已执行验证结果中。

许可证、原代码与贡献权属、Maven 命名空间权限和安全联系渠道仍需维护者确认。本记录不表示已创建正式版本标签、发布 Maven 包或发布 GitHub 安全公告。源码推送与正式制品发布分别管理。
