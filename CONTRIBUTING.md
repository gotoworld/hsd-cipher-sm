# Contributing

请先阅读 README、SECURITY.md 和迁移说明。修复或功能请求应提供非生产样本、运行环境、依赖树、明确的格式与预期行为；不要提交密钥、业务明文或客户密文。

开发要求 JDK 8+ 与 Maven 3.6.3+。运行 `mvn -B clean verify`；涉及密码格式、密钥或 provider 升级时，还需运行 `mvn -B clean verify -Dopenssl.integration=true`，并在安装主包后运行 `bash examples/run.sh`。

安全问题使用 SECURITY.md 所述渠道；公开 issue 不应包含尚未处理的可利用细节。普通问题可以使用 GitHub issue。新增功能应包含具体用户场景、明确字节与格式契约、成功与拒绝场景断言、文档和兼容性影响。固定随机数仅能存在于非生产测试向量，不得成为公开运行配置。

不要暴露 provider 内部类型作为新的稳定接口。legacy 只用于读取与历史验证，不增加旧曲线写入。internal 包不属于支持的外部接口。依赖升级应一起检查向量、OpenSSL、JDK 与历史 fixtures；不要为了测试通过跳过完整性或输入校验。

许可证与旧代码权属待维护者确认时，请先与维护者明确贡献授权；本文件不代替权利人的许可声明。提交前使用 `git diff --check` 检查格式，并确认没有生成物或敏感信息。
