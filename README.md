# Profiles

Surge、Mihomo 系 Clash（包括 Clash.MD/Hako）与 Shadowrocket 的公共规则和配置模板。提供出国、回国、仅过滤三种场景，不包含节点、订阅凭据、证书或个人设备设置。

| 场景 | Surge | Clash / Clash.MD | Shadowrocket |
| --- | --- | --- | --- |
| 出国：国内直连，其他代理 | [Outbound.conf](Surge/Outbound.conf) | [Outbound.yaml](Clash/Outbound.yaml) | [Outbound.conf](Shadowrocket/Outbound.conf) |
| 回国：海外直连，中国流媒体及中国 IP 可选择回国代理 | [Inbound.conf](Surge/Inbound.conf) | [Inbound.yaml](Clash/Inbound.yaml) | [Inbound.conf](Shadowrocket/Inbound.conf) |
| 仅过滤：过滤后直连 | [FilterOnly.conf](Surge/FilterOnly.conf) | [FilterOnly.yaml](Clash/FilterOnly.yaml) | [FilterOnly.conf](Shadowrocket/FilterOnly.conf) |

使用规则模式。Surge/Clash 出国模板没有节点，Proxies 初始 REJECT；请下载到本地副本后添加自己的节点。Shadowrocket 使用首页管理的节点，通过 PROXY 策略引用。回国组初始 DIRECT，需配置并选择具有大陆出口的节点后才启用回国代理。Guard 默认 REJECT，可临时切到 DIRECT 排查公共过滤误杀。AI、Netflix、Apple 和 Bilibili 可分别选择策略。

## 规则来源与优先级

使用 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 的客户端专用资源：AdvertisingLite、Hijacking、Privacy、China、Apple、OpenAI、Claude、Google、GitHub、Telegram、Netflix、YouTube、BiliBili、ChinaMedia。

AI 服务另有补充来源 [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules)（MIT）的 anthropic、openai、google-ai、copilot 四类：上游 OpenAI 与 Claude 列表停在 2025-06-06，Claude 仅 3 条，缺少 `claude.com`、`claudeusercontent.com`、MCP 域名、`sora.com`、`chat.com`、Gemini 与 Copilot；补充规则在过滤之后分类，出国指向 `AI`（Copilot 为独立 `Copilot` 组），回国明确直连，仅过滤场景不引用。两处来源各自锁定提交，见 [sources.lock.json](config/sources.lock.json) 的 `commit` 与 `ai.commit`。

源版本锁定在 [sources.lock.json](config/sources.lock.json)，记录完整提交 SHA、每个文件的 SHA-256、条数和源文件更新时间。AdvertisingLite、Privacy、China、Apple 的 domain 与 classical 文件分别引用，避免漏掉上游拆分的域名列表。客户端刷新同一 URL 不会越过锁定版本；更新需运行下方 refresh 命令并发布新的模板。

顺序为本地/私网直连、过滤例外、个人屏蔽、连通性放行、广告/劫持/Privacy 过滤、AI 分类、服务分类、地区判断、最终策略。出国场景另启用 Privacy；回国采用 ChinaMedia 和 GEOIP CN，并将常见海外服务优先直连，不把包含海外直连例外的整份 China 列表当作回国列表。`filter_exceptions` 仅在出国场景把 `featuregates.org`、`statsig.anthropic.com`、`sentry.io`、`segment.io` 精确放到全部 Guard 规则之前，其余过滤顺序不变，回国与仅过滤场景不生成例外；因此出现在 Privacy 里的其他供应商域名仍会被 Guard 拦截，这也是 Guard 默认 REJECT 提供临时 DIRECT 排查的原因。公共模板没有个人域名屏蔽或个人应用例外。

## 更新与验证

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tools/profiles.py fetch
.venv/bin/python tools/validate.py
.venv/bin/python tools/check_public.py
```

更新上游并审查变化：

```sh
.venv/bin/python tools/profiles.py refresh
.venv/bin/python tools/validate.py
.venv/bin/python tools/check_public.py
git diff --stat
git diff -- config/
```

`refresh` 解析上游最新 master，验证全部资源后更新锁文件和九份模板；`refresh --ref <完整提交SHA>` 可选定版本。`fetch` 只下载锁定资源；`build` 根据当前 [policy.json](config/policy.json) 和锁文件重建模板。这里的 policy 只维护公共策略，私人设置应保存在仓库外。

可选 Mihomo 原生格式校验：`tools/validate.py --mihomo /path/to/mihomo --mmdb /path/to/Country.mmdb`。只执行 `-t`，不启动服务。提交前运行 `tools/check_public.py --staged` 检查实际暂存内容。

## 客户端兼容与迁移

Clash 使用 Mihomo 支持的 rule-providers、策略组和 DNS 字段；[Clash.MD](https://clash.md/) 的 Hako 基于 Mihomo。共同模板不设置桌面 TUN 路由、对外监听或控制端口，由客户端管理。旧 Clash Premium/经典 Clash 不在此次兼容范围。格式验证不等于所有客户端版本、VPN 扩展和真实节点的连接验证。

Surge 原有 `Surge/Outbound.conf` 与 `Surge/Inbound.conf` 入口已更新为新模板。原 `Surge/Ruleset`、`Clash/RuleSet`、模块、重写和 Quantumult 目录保留作历史兼容资源，**本次未更新，新的模板也不依赖它们**。旧用户需要主动迁移配置入口；单独订阅历史规则文件不会自动获得新版数据。过时的说明保存在 [历史 README](docs/LEGACY-README.md) 与 [历史 Surge 说明](docs/LEGACY-Surge-README.md)，其中旧链接仅供追溯。

参见 [本次更新记录](docs/UPDATE-2026-09-06.md) 与 [上游刷新与 AI 规则补充](docs/UPDATE-2026-09-29.md)。

## 来源

规则数据来自 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) 与 [VPSDance/ai-proxy-rules](https://github.com/VPSDance/ai-proxy-rules)，以远程 URL 方式引用，不纳入本仓库；下载缓存同样不纳入仓库。历史规则及作者致谢保留在历史 README。Shadowrocket 格式参考 [LOWERTOP/Shadowrocket](https://github.com/LOWERTOP/Shadowrocket) 的维护者示例。

## 可选个人屏蔽列表

另提供独立的 [Custom/Blocklists](Custom/Blocklists/README.md)：Outbound 屏蔽知乎相关域名，FilterOnly 包含百度、GitLab、拼多多及指定视频域名。三端均有专用规则文件，主模板默认不加载，按说明绑定 REJECT 即可选用。这些公开列表只含域名匹配规则，不包含私人节点、设备或订阅信息。
