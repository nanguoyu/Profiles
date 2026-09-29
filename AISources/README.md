# AISources — 生成产物，请勿手动编辑

这里保存 AI 补充规则在本仓库的**快照**，按 Surge / Clash / Shadowrocket 三端各一份。六类来自 [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules) 的 anthropic、openai、google-ai、x-ai、perplexity、copilot；另有 `ai-extra`（三端各一份，共 21 个文件）完全来自本仓库 `config/policy.json` 的 `ai_extra`。

上传到公网的原因：客户端的规则引擎只能下载整份远程列表，无法只排除其中某一条规则。上游 anthropic 列表里的 `DOMAIN-KEYWORD,sift` 会连带命中无关的 `siftscience.com`，因此必须在本仓库提供一份剔除了该关键词的列表，模板引用本仓库路径后修复才会真正生效。

- 内容来源：`config/sources.lock.json` 中 `ai.commit` 锁定的上游提交，原始文件的 SHA-256 也记录在同一处，用于追溯与漂移检测。`ai-extra.*` 没有上游对应文件，全部来自 `ai_extra`。
- 过滤规则：`config/policy.json` 的 `source_denylist`（当前为 `anthropic` 的 `DOMAIN-KEYWORD,sift` 与 `copilot` 的 `IP-ASN,14061,no-resolve`）。
- 重新生成：`tools/profiles.py build`（离线，按锁定哈希校验缓存）或 `tools/profiles.py refresh`（连同上游基线一起更新）。
- 校验：`tools/validate.py` 会检查快照与锁定源一致、关键词已被剔除、模板确实引用快照而未引用上游。

手动修改这里的文件会在下一次 `build` 时被覆盖；要调整内容请改 `config/policy.json`。
