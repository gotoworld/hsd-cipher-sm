# 发布检查

2.0.0-SNAPSHOT 是本地开发坐标，不代表已在公共仓库发布。旧内网 Nexus 配置已经移除；没有配置自动公开发布或上传凭据。

发布前必须完成：

- 确认原代码、贡献和资料权属，添加已获授权的 LICENSE、版权信息、必要的 NOTICE 和 POM licenses。
- 确认 Maven groupId 的发布权限、维护者身份和私密安全报告渠道，不把历史公司命名空间视为已获发布授权。
- 在支持的 JDK 执行 `mvn -B clean verify -Dopenssl.integration=true`，安装到本地后运行独立消费者。
- 复查 CHANGELOG、迁移说明、安全问题受影响范围、依赖树与新版本测试记录。
- 检查主 jar、sources jar、javadoc jar，无历史危险类、临时验证文件、真实密钥或敏感信息。
- 使用维护者选择的发布渠道配置签名与凭据，先验证可供检查的发布包，再经维护者授权公开发布。

本地验证命令：

```sh
mvn -B clean install -Dopenssl.integration=true
bash examples/run.sh
jar tf target/hsd-cipher-sm-2.0.0-SNAPSHOT.jar
```

许可证、命名空间权限和安全联系未确认时，不应将开发包声明为已经可以公开分发的正式开源版本。已确认后再设置正式版本、创建标签并发布；本次修复没有执行这些外部操作。
