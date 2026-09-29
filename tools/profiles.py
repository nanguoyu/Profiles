"""Build credential-free, three-client profiles from pinned and verified public rules."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / 'config'
PROFILE_NAMES = {'科学上网': 'Outbound', '回国': 'Inbound', '只过滤不代理': 'FilterOnly'}
REPO = 'blackmatrix7/ios_rule_script'
AI_REPO = 'VPSDance/ai-proxy-rules'
AI_PREFIX = 'AI:'
CLIENTS = ('Surge', 'Clash', 'Shadowrocket')
POLICY = json.loads((CONFIG / 'policy.json').read_text())
LOCK = CONFIG / 'sources.lock.json'
CACHE = ROOT / '.cache' / 'rules'
AI_CACHE = ROOT / '.cache' / 'ai-rules'
SNAPSHOT = ROOT / 'AISources'
TEST_URL = 'https://cp.cloudflare.com/generate_204'
SOURCE_GROUPS = ('clients', 'ai')
# Where the locally served AI snapshots are published; override in policy.json for a fork.
RAW_BASE = POLICY.get('raw_base', 'https://raw.githubusercontent.com/nanguoyu/Profiles/main/')


def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def get(url, optional=False):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Public-Profiles/1.0'})
        with urllib.request.urlopen(req, timeout=40) as response:
            data = response.read(8_000_001)
        if len(data) > 8_000_000:
            raise ValueError('Public rule resource exceeded size limit')
        return data
    except urllib.error.HTTPError as e:
        if optional and e.code == 404:
            return None
        raise


def entries(data, kind, client, category=None):
    text = data.decode('utf-8-sig')
    if client == 'Clash':
        parsed = yaml.safe_load(text)
        if not isinstance(parsed, dict) or not isinstance(parsed.get('payload'), list):
            raise ValueError('Expected a YAML rule-provider payload')
        result = parsed['payload']
    else:
        result = [x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith(('#', '//', ';'))]
    if not result or not all(isinstance(x, str) for x in result):
        raise ValueError('Empty or malformed public rules')
    if kind == 'domain':
        if any(',' in x or '://' in x or '<' in x or ' ' in x for x in result):
            raise ValueError('Invalid domain payload')
    else:
        allowed = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'USER-AGENT', 'PROCESS-NAME', 'PROCESS-PATH', 'URL-REGEX', 'AND', 'OR', 'NOT', 'DST-PORT', 'DEST-PORT', 'NETWORK', 'PROTOCOL'}
        if any(x.split(',')[0] not in allowed for x in result):
            raise ValueError('Unexpected rule type or embedded policy in source')
    # A declared keyword denylist drops entries that are broader than the source intended, e.g.
    # sift also captures unrelated siftscience.com. Every caller filters through here so the
    # lock entry count stays the count that actually reaches the generated profiles.
    denied = {x.strip().lower() for x in POLICY.get('keyword_denylist', {}).get(category, [])}
    if denied:
        result = [x for x in result if x.strip().lower() not in denied]
        if not result:
            raise ValueError('Keyword denylist removed every entry of ' + str(category))
    return result


def load_resource(cache, ref, key, url, kind, client, category, optional=False):
    data = get(url, optional=optional)
    if data is None:
        return None
    parsed = entries(data, kind, client, category)
    atomic(cache / ref / key, data)
    updated = re.search(r'^# UPDATED:\s*(.+)$', data.decode('utf-8-sig'), re.M)
    return {'key': key, 'kind': kind, 'url': url, 'sha256': hashlib.sha256(data).hexdigest(),
            'bytes': len(data), 'entries': len(parsed), 'source_updated': updated[1] if updated else None}


def discover_ai(ref, client, provider):
    """Supplemental AI rules ship one classical file per provider and client."""
    extension = '.yaml' if client == 'Clash' else '.list'
    url = f'https://raw.githubusercontent.com/{AI_REPO}/{ref}/rules/{client.lower()}/{provider}{extension}'
    resource = load_resource(AI_CACHE, ref, f'{client}-AI-{provider}', url, 'classical', client, provider)
    if resource is None:
        raise ValueError(f'{AI_REPO} is missing {client}/{provider}')
    return client, provider, [resource]


def discover(ref, client, category):
    base = f'https://raw.githubusercontent.com/{REPO}/{ref}/rule/{client}/{category}/'
    resources = []
    filenames = [('domain', category + ('_Domain.yaml' if client == 'Clash' else '_Domain.list')),
                 ('classical', category + ('.yaml' if client == 'Clash' else '.list'))]
    for kind, filename in filenames:
        resource = load_resource(CACHE, ref, f'{client}-{category}-{kind}', base + filename, kind, client, category,
                                 optional=(kind == 'domain'))
        if resource is not None:
            resources.append(resource)
    # A split source cannot silently become a tiny incomplete classical list.
    text = (CACHE / ref / f'{client}-{category}-classical').read_text()
    counts = re.findall(r'^# (?:DOMAIN|DOMAIN-SUFFIX):\s*(\d+)', text, re.M)
    advertised = sum(map(int, counts))
    actual_classical = entries(text.encode(), 'classical', client, category)
    actual_domains = sum(x.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,')) for x in actual_classical)
    if advertised > actual_domains + 10 and not any(x['kind'] == 'domain' for x in resources):
        raise ValueError(f'{client}/{category}: missing domain companion')
    return client, category, resources


def refresh(ref=None, ai_ref=None):
    if ref is None:
        data = json.loads(get(f'https://api.github.com/repos/{REPO}/commits/master'))
        ref = data['sha']
    if not re.fullmatch('[a-f0-9]{40}', ref):
        raise ValueError('Use a full immutable commit SHA')
    if ai_ref is None:
        ai_ref = json.loads(get(f'https://api.github.com/repos/{AI_REPO}/commits/main'))['sha']
    if not re.fullmatch('[a-f0-9]{40}', ai_ref):
        raise ValueError(f'Use a full immutable commit SHA for {AI_REPO}')
    result = {'schema': 1, 'repository': REPO, 'commit': ref, 'clients': {c: {} for c in CLIENTS}}
    jobs = [(ref, c, name) for c in CLIENTS for name in POLICY['sources']]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(discover, *args) for args in jobs]
        for future in concurrent.futures.as_completed(futures):
            client, name, resources = future.result()
            result['clients'][client][name] = resources
            print(f'{client}/{name}: {sum(x["entries"] for x in resources)} entries')
    result['ai'] = {'repository': AI_REPO, 'commit': ai_ref, 'clients': {c: {} for c in CLIENTS}}
    ai_jobs = [(ai_ref, c, name) for c in CLIENTS for name in POLICY['ai_sources']]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(discover_ai, *args) for args in ai_jobs]
        for future in concurrent.futures.as_completed(futures):
            client, name, resources = future.result()
            result['ai']['clients'][client][name] = resources
            print(f'{client}/{name}: {sum(x["entries"] for x in resources)} entries')
    # Publish the lock only once every selected source has been validated.
    atomic(LOCK, json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    generate()


def load_lock():
    lock = json.loads(LOCK.read_text())
    assert lock['repository'] == REPO and re.fullmatch('[a-f0-9]{40}', lock['commit'])
    assert lock['ai']['repository'] == AI_REPO and re.fullmatch('[a-f0-9]{40}', lock['ai']['commit'])
    return lock


def resources(lock):
    """Every pinned resource, whatever source group it belongs to."""
    for group in SOURCE_GROUPS:
        section = lock['ai'] if group == 'ai' else lock
        cache = AI_CACHE if group == 'ai' else CACHE
        for client, categories in section['clients'].items():
            for name, parts in categories.items():
                for resource in parts:
                    yield cache, section['commit'], client, name, resource


def hydrate(lock, network=False):
    jobs = list(resources(lock))
    def one(job):
        cache, ref, _client, _name, resource = job
        path = cache / ref / resource['key']
        if not path.exists():
            if not network:
                raise ValueError('Missing cached source. Run: tools/profiles.py fetch')
            data = get(resource['url'])
            if hashlib.sha256(data).hexdigest() != resource['sha256']:
                raise ValueError('Source checksum mismatch: ' + resource['key'])
            atomic(path, data)
        if hashlib.sha256(path.read_bytes()).hexdigest() != resource['sha256']:
            raise ValueError('Cached source checksum mismatch: ' + resource['key'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(one, jobs))


def logical_rules(scene, client):
    """A single routing order; rendering handles per-client syntax and resources."""
    p = POLICY['scenes'][scene]
    rules = []
    def literal(expression, target):
        rules.append(('literal', expression, target))
    def resource(name, target):
        rules.append(('resource', name, target))
    for domain in ('local', 'lan'):
        literal('DOMAIN-SUFFIX,' + domain, 'DIRECT')
    if client == 'Surge':
        literal('DOMAIN-SUFFIX,sgponte', 'DIRECT')
    for net in ('127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10'):
        literal('IP-CIDR,' + net + ',no-resolve', 'DIRECT')
    for net in ('::1/128', 'fc00::/7', 'fe80::/10'):
        literal('IP-CIDR6,' + net + ',no-resolve', 'DIRECT')
    # A few AI vendor endpoints also appear in the pinned Privacy/Advertising lists and would be
    # rejected by Guard before service classification. Emitting these exact expressions before
    # every Guard rule is the only bypass; 回国 and 仅过滤 keep the pinned filtering untouched.
    if scene == '科学上网':
        for expression, filter_policy in POLICY['filter_exceptions'].items():
            literal(expression, filter_policy)
    for expression in p['blocks']:
        literal(expression, 'REJECT')
    for expression in p['proxy_overrides']:
        literal(expression, 'Proxies')
    for expression in POLICY['direct_exceptions']:
        literal(expression, 'DIRECT')
    for expression in POLICY['google_exceptions']:
        literal(expression, 'Proxies' if scene == '科学上网' else 'DIRECT')
    resource('AdvertisingLite', 'Guard')
    resource('Hijacking', 'Guard')
    if p['privacy']:
        resource('Privacy', 'Guard')
    # Preserve desktop download exceptions only in the Surge adapter; not portable app matching.
    if client == 'Surge' and scene != '只过滤不代理':
        for process in POLICY['download_processes']:
            literal('PROCESS-NAME,' + process, 'DIRECT')
    if scene != '只过滤不代理':
        # Supplemental AI rules refine the classification of the pinned OpenAI/Claude lists.
        # 科学上网 sends them to their own selectable group; 回国 keeps them explicitly direct.
        # The AI: name keeps the lock lookup apart from the blackmatrix7 categories.
        for name, group in POLICY['ai_sources'].items():
            resource(AI_PREFIX + name, group if scene == '科学上网' else 'DIRECT')
    if scene == '科学上网':
        for name, target in [('OpenAI', 'AI'), ('Claude', 'AI'), ('Telegram', 'Proxies'), ('Netflix', 'Netflix'), ('YouTube', 'Proxies'), ('Google', 'Proxies'), ('GitHub', 'Proxies'), ('BiliBili', 'Bilibili'), ('Apple', 'Apple'), ('China', 'DIRECT')]:
            resource(name, target)
        literal('GEOIP,CN', 'DIRECT')
    elif scene == '回国':
        # China contains overseas direct exceptions (e.g. Microsoft); never use it as a return list.
        resource('ChinaMedia', '回国代理')
        for name in ('Apple', 'Google', 'GitHub', 'OpenAI', 'Claude', 'Telegram', 'Netflix', 'YouTube'):
            resource(name, 'DIRECT')
        literal('GEOIP,CN', '回国代理')
    literal('FINAL', p['final'])
    return rules


def attach(expression, target, client):
    if expression == 'FINAL':
        return ('MATCH' if client == 'Clash' else 'FINAL') + ',' + target
    parts = expression.split(',')
    if parts[-1] == 'no-resolve':
        return ','.join(parts[:-1] + [target, 'no-resolve'])
    return expression + ',' + target


def category_resources(lock, client, name):
    """Supplemental AI sources live under lock['ai'] with their own pinned commit."""
    section = lock['ai'] if name.startswith(AI_PREFIX) else lock
    category = name[len(AI_PREFIX):] if name.startswith(AI_PREFIX) else name
    return section['clients'][client][category], section['commit']


def snapshot_path(client, provider, kind):
    extension = '.yaml' if client == 'Clash' else '.list'
    return SNAPSHOT / client / (provider + extension)


def snapshot_payload(lock, client, provider, resource):
    """Filtered entries of one AI supplement, read from the verified cache."""
    data = (AI_CACHE / lock['ai']['commit'] / resource['key']).read_bytes()
    return entries(data, resource['kind'], client, provider)


def snapshot_bytes(lock, client, provider, resource):
    payload = snapshot_payload(lock, client, provider, resource)
    header = (f'# Snapshot of {AI_REPO} at {lock["ai"]["commit"]}\n'
              f'# Filtered locally by keyword_denylist in config/policy.json; do not edit by hand.\n'
              f'# Regenerate with: tools/profiles.py refresh (or build)\n')
    if client == 'Clash':
        return header + yaml.safe_dump({'payload': payload}, allow_unicode=True, sort_keys=False)
    return header + '\n'.join(payload) + '\n'


def snapshot_ai(lock):
    for client in CLIENTS:
        for provider, parts in lock['ai']['clients'][client].items():
            for resource in parts:
                atomic(snapshot_path(client, provider, resource['kind']),
                       snapshot_bytes(lock, client, provider, resource))


def snapshot_url(lock, client, name, resource):
    """AI supplements are served from this repository; other sources stay pinned upstream."""
    if not name.startswith(AI_PREFIX):
        return resource['url']
    provider = name[len(AI_PREFIX):]
    return RAW_BASE + 'AISources/' + client + '/' + snapshot_path(client, provider, resource['kind']).name


def rendered_rules(scene, client, lock):
    rules, providers = [], {}
    for kind, expression, target in logical_rules(scene, client):
        if kind == 'literal':
            rules.append(attach(expression, target, client))
            continue
        section, commit = category_resources(lock, client, expression)
        for resource in section:
            url = snapshot_url(lock, client, expression, resource)
            if client == 'Clash':
                # Provider names and cache paths stay free of the AI: namespace used for lookups.
                name = expression.removeprefix(AI_PREFIX) + '-' + resource['kind']
                providers[name] = {'type': 'http', 'behavior': resource['kind'], 'format': 'yaml',
                                   'url': url, 'path': './rules/' + name + '-' + commit[:12] + '.yaml', 'interval': 86400}
                rules.append(f'RULE-SET,{name},{target}' + (',no-resolve' if resource['kind'] == 'classical' else ''))
            else:
                prefix = 'DOMAIN-SET' if resource['kind'] == 'domain' else 'RULE-SET'
                rules.append(f'{prefix},{url},{target}' + (',no-resolve' if prefix == 'RULE-SET' else ''))
    return rules, providers


def basic_groups(scene, client):
    groups = {'Guard': ['REJECT', 'DIRECT']}
    if scene == '科学上网':
        # Safe template: no fictitious endpoint and no accidental direct fallback for proxy traffic.
        groups['Proxies'] = ['PROXY'] if client == 'Shadowrocket' else ['REJECT']
        groups.update({'AI': ['Proxies'], 'Netflix': ['Proxies'], 'Apple': ['DIRECT', 'Proxies'], 'Bilibili': ['DIRECT', 'Proxies']})
    elif scene == '回国':
        groups['回国代理'] = ['DIRECT', 'PROXY'] if client == 'Shadowrocket' else ['DIRECT']
    if scene == '科学上网':
        # Supplemental AI sources are referenced by the AI/Copilot groups, which only exist here.
        for target in dict.fromkeys(POLICY['ai_sources'].values()):
            if target not in groups:
                groups[target] = ['DIRECT', 'Proxies']
    return groups


def conf_section(name, lines):
    return '[' + name + ']\n' + '\n'.join(lines) + '\n\n'


def conf(scene, client, lock):
    lines, _ = rendered_rules(scene, client, lock)
    header = f'# {scene} | {client} | rules {lock["commit"][:12]} | ai {lock["ai"]["commit"][:12]}\n'
    header += '# 公共模板不含节点。使用规则模式；自定义公共策略后重新生成。\n'
    header += '# 回国出口未确认时保持 DIRECT；测速不判断地区解锁。\n'
    header += '# Shadowrocket 节点在首页管理；Surge 模板请在本地副本中添加节点。\n\n'
    general = ['loglevel = notify', 'dns-server = system', 'ipv6 = true', 'skip-proxy = localhost, *.local, 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10', 'udp-policy-not-supported-behaviour = REJECT']
    if client == 'Surge':
        general += ['ipv6-vif = auto', 'http-listen = 127.0.0.1:6152', 'socks5-listen = 127.0.0.1:6153', 'allow-wifi-access = false', 'internet-test-url = http://bing.com/', 'proxy-test-url = ' + TEST_URL]
    else:
        general += ['private-ip-answer = true', 'dns-direct-fallback-proxy = false']
    result = header + conf_section('General', general)
    result += conf_section('Proxy Group', [name + ' = select, ' + ', '.join(members) for name, members in basic_groups(scene, client).items()])
    result += conf_section('Rule', lines)
    return result.rstrip() + '\n'


def clash(scene, lock):
    rules, providers = rendered_rules(scene, 'Clash', lock)
    nameservers = ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'] if scene == '科学上网' else ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query']
    data = {'mode': 'rule', 'log-level': 'warning', 'ipv6': True, 'profile': {'store-selected': True},
            'dns': {'enable': True, 'ipv6': True, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                    'fake-ip-filter': ['*.lan', '*.local', '+.ts.net', 'localhost'],
                    'default-nameserver': ['223.5.5.5', '1.1.1.1'], 'nameserver': nameservers,
                    'proxy-server-nameserver': nameservers},
            'proxies': [], 'proxy-groups': [{'name': name, 'type': 'select', 'proxies': members} for name, members in basic_groups(scene, 'Clash').items()],
            'rule-providers': providers, 'rules': rules}
    return data


def generate_blocklists():
    blocklists = json.loads((CONFIG / 'blocklists.json').read_text())
    for name, rules in blocklists.items():
        if not re.fullmatch('[A-Za-z]+', name):
            raise ValueError('Invalid blocklist filename')
        if not rules or any(len(r.split(',')) != 2 or r.split(',')[0] not in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD') for r in rules):
            raise ValueError('Blocklists must contain only domain rules without policies')
        for client in CLIENTS:
            data = '# Optional personal blocklist; apply with REJECT before general routing.\n'
            if client == 'Clash':
                data += yaml.safe_dump({'payload': rules}, allow_unicode=True, sort_keys=False)
                extension = '.yaml'
            else:
                data += '\n'.join(rules) + '\n'
                extension = '.list'
            atomic(ROOT / 'Custom' / 'Blocklists' / client / (name + extension), data)


def generate():
    lock = load_lock()
    snapshot_ai(lock)
    for scene in POLICY['scenes']:
        for client in CLIENTS:
            if client == 'Clash':
                header = '# Mihomo / Clash.MD 通用配置。Apple Packet Tunnel 由客户端管理；不设置桌面 TUN 路由。\n# 无内置节点的公共模板请先添加节点，或在本地副本中配置自己的节点。\n'
                data = header + yaml.safe_dump(clash(scene, lock), allow_unicode=True, sort_keys=False)
                name = PROFILE_NAMES[scene] + '.yaml'
            else:
                data, name = conf(scene, client, lock), PROFILE_NAMES[scene] + '.conf'
            atomic(ROOT / client / name, data)
    generate_blocklists()
    print('Generated 9 public profiles and optional blocklists. No private credentials loaded.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['refresh', 'fetch', 'build'])
    parser.add_argument('--ref', help='Full immutable upstream commit SHA; otherwise refresh resolves master')
    parser.add_argument('--ai-ref', help='Full immutable AI supplement commit SHA; otherwise refresh resolves main')
    args = parser.parse_args()
    if args.command == 'refresh':
        refresh(args.ref, args.ai_ref)
    elif args.command == 'fetch':
        hydrate(load_lock(), network=True)
    else:
        generate()


if __name__ == '__main__':
    main()
