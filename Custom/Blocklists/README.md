# 可选个人屏蔽规则

这些是独立、可选的规则文件，不包含节点或凭据，也不由主模板默认加载。

| 文件 | 屏蔽内容 |
| --- | --- |
| Outbound | 域名包含 `zhihu` |
| FilterOnly | 域名包含 `gitlab`、`baidu`、`pdd`、`video.weibocdn.com`，以及列出的五个小红书视频域名 |

使用 DOMAIN-KEYWORD 保持原有屏蔽范围，因此也可能匹配其他包含这些文字的域名。请按需要选用；希望缩小范围时可改为 DOMAIN 或 DOMAIN-SUFFIX。

源文件为 [config/blocklists.json](../../config/blocklists.json)。修改后执行 `tools/profiles.py build`，会生成 Surge、Clash、Shadowrocket 三种格式。文件本身不指定动作，使用时绑定 REJECT。

## Surge / Shadowrocket

在对应客户端配置的 `[Rule]` 中，放在公共过滤、China、GEOIP 和 FINAL 等规则之前。两者使用各自的目录，例如 Surge 出国屏蔽：

```ini
RULE-SET,https://raw.githubusercontent.com/nanguoyu/Profiles/main/Custom/Blocklists/Surge/Outbound.list,REJECT
```

Shadowrocket 仅过滤场景：

```ini
RULE-SET,https://raw.githubusercontent.com/nanguoyu/Profiles/main/Custom/Blocklists/Shadowrocket/FilterOnly.list,REJECT
```

两个客户端均可选用 Outbound.list 或 FilterOnly.list；二者互不包含。如需全部屏蔽，可同时添加两条。这里提供普通 RULE-SET，而非优先级独立于主配置的 Shadowrocket 模块，便于明确规则顺序。

## Clash / Clash.MD

将以下条目合并进现有 `rule-providers`，不要建立第二个同名顶层字段：

```yaml
rule-providers:
  PersonalBlock:
    type: http
    behavior: classical
    format: yaml
    url: https://raw.githubusercontent.com/nanguoyu/Profiles/main/Custom/Blocklists/Clash/FilterOnly.yaml
    path: ./rules/personal-block-filter.yaml
    interval: 86400
```

将 `RULE-SET,PersonalBlock,REJECT` 放入现有 `rules` 列表，置于公共过滤、地区判断和 MATCH 之前。需要出国场景屏蔽时，使用 `Outbound.yaml`；同时使用两份时设置不同 provider 名称和缓存路径。

上面的可选个人列表 URL 跟随本仓库 main，便于单独更新；需要固定版本时把 `main` 换成具体提交 SHA。主模板的第三方公共规则仍由 sources.lock.json 锁定。
