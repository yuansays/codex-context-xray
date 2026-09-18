# 发布草稿 — 中文

> 仅为草稿。发布前请确认措辞，并根据具体社区规则调整。

## 短版

我做了一个开源小工具：Codex Context X-Ray。它会在 Codex 开始工作前，
解释哪些指令、配置、Skills、MCP、hooks、命令规则和权限会被加载，哪些会被
覆盖、忽略或保持条件状态。

它不靠模型猜语义，而是复现已公开的加载顺序和优先级，生成一个可点击、
单文件、完全离线的 HTML 因果图。每个节点都能看到来源、状态、覆盖原因和
脱敏后的安全摘录。

默认只读当前仓库，不联网、零遥测、不执行仓库代码，也不会读取认证文件、
会话、浏览器数据、日志、数据库或环境变量值。只有显式加
`--include-user` 才会检查用户级配置。

```bash
pipx install "git+https://github.com/yuansays/codex-context-xray.git@v0.1.0"
codex-xray demo --open
codex-xray scan . --format html --output codex-xray.html --open
```

项目地址：https://github.com/yuansays/codex-context-xray

如果报告与当前 Codex 行为不一致，欢迎提交最小化、完全虚构的兼容性样例。
请不要在 Issue 中上传私人配置或真实凭据。

## 备选标题

开源了一个 Codex 上下文 X 光：开工前看清哪些配置真正生效

## 发布前检查

- 只使用 `docs/assets/demo.gif` 中的虚构演示，不展示真实项目配置。
- 不添加未经验证的用户数、Star、效率提升或兼容性结论。
- 安装命令固定到 Release 标签，不引导安装未固定的主分支。
- 根据目标社区规则改写开头和结尾，避免重复灌水式投放。
