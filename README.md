# yakit-hotpatch-skill

用于指导 AI 编写 Yakit Web Fuzzer 热加载代码。

## 功能

提供 Yakit Web Fuzzer 热加载的完整 API 参考和编码模式，包括：

- **自定义 fuzztag 函数**：`{{yak(name|param)}}` 调用的用户定义函数
- **魔术方法**：`beforeRequest`（请求修改）、`afterRequest`（响应修改）
- **高级钩子**：`mirrorHTTPFlow`（数据提取）、`retryHandler`（重试控制）、`customFailureChecker`（失败判断）、`mockHTTPRequest`（Mock 响应）
- **常用标准库速查**：`codec`、`poc`、`xpath`、`json` 等
- **实战案例**：CSRF token 绕过、AES 加密爆破、请求签名等

## 安装

skill 文件位于 `~/.claude/skills/yakit-hotpatch-skill/SKILL.md`。Claude Code 会在用户请求编写热加载代码时自动加载。

## 知识来源

- [yaklang](https://github.com/yaklang/yaklang) 源码（`common/yak/script_engine_for_fuzz.go`）
- [Yaklang 官方文档](https://yaklang.com/products/Web%20Fuzzer/fuzz-hotpatch)
