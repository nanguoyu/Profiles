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
CLIENTS = ('Surge', 'Clash', 'Shadowrocket')
POLICY = json.loads((CONFIG / 'policy.json').read_text())
LOCK = CONFIG / 'sources.lock.json'
CACHE = ROOT / '.cache' / 'rules'
TEST_URL = 'https://cp.cloudflare.com/generate_204'


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


def entries(data, kind, client):
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
        allowed = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'USER-AGENT', 'PROCESS-NAME', 'PROCESS-PATH', 'URL-REGEX', 'AND', 'OR', 'NOT', 'DST-PORT', 'DEST-PORT', 'NETWORK', 'PROTOCOL'}
        if any(x.split(',')[0] not in allowed for x in result):
            raise ValueError('Unexpected rule type or embedded policy in source')
    return result


def discover(ref, client, category):
    base = f'https://raw.githubusercontent.com/{REPO}/{ref}/rule/{client}/{category}/'
    resources = []
    filenames = [('domain', category + ('_Domain.yaml' if client == 'Clash' else '_Domain.list')),
                 ('classical', category + ('.yaml' if client == 'Clash' else '.list'))]
    for kind, filename in filenames:
        url = base + filename
        data = get(url, optional=(kind == 'domain'))
        if data is None:
            continue
        parsed = entries(data, kind, client)
        key = f'{client}-{category}-{kind}'
        atomic(CACHE / ref / key, data)
        updated = re.search(r'^# UPDATED:\s*(.+)$', data.decode('utf-8-sig'), re.M)
        resources.append({'key': key, 'kind': kind, 'url': url, 'sha256': hashlib.sha256(data).hexdigest(),
                          'bytes': len(data), 'entries': len(parsed), 'source_updated': updated[1] if updated else None})
    # A split source cannot silently become a tiny incomplete classical list.
    text = (CACHE / ref / f'{client}-{category}-classical').read_text()
    counts = re.findall(r'^# (?:DOMAIN|DOMAIN-SUFFIX):\s*(\d+)', text, re.M)
    advertised = sum(map(int, counts))
    actual_classical = entries(text.encode(), 'classical', client)
    actual_domains = sum(x.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,')) for x in actual_classical)
    if advertised > actual_domains + 10 and not any(x['kind'] == 'domain' for x in resources):
        raise ValueError(f'{client}/{category}: missing domain companion')
    return client, category, resources


def refresh(ref=None):
    if ref is None:
        data = json.loads(get(f'https://api.github.com/repos/{REPO}/commits/master'))
        ref = data['sha']
    if not re.fullmatch('[a-f0-9]{40}', ref):
        raise ValueError('Use a full immutable commit SHA')
    result = {'schema': 1, 'repository': REPO, 'commit': ref, 'clients': {c: {} for c in CLIENTS}}
    jobs = [(ref, c, name) for c in CLIENTS for name in POLICY['sources']]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(discover, *args) for args in jobs]
        for future in concurrent.futures.as_completed(futures):
            client, name, resources = future.result()
            result['clients'][client][name] = resources
            print(f'{client}/{name}: {sum(x["entries"] for x in resources)} entries')
    # Publish the lock only once every selected source has been validated.
    atomic(LOCK, json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    generate()


def load_lock():
    lock = json.loads(LOCK.read_text())
    assert lock['repository'] == REPO and re.fullmatch('[a-f0-9]{40}', lock['commit'])
    return lock


def hydrate(lock, network=False):
    jobs = [r for categories in lock['clients'].values() for resources in categories.values() for r in resources]
    def one(resource):
        path = CACHE / lock['commit'] / resource['key']
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


def rendered_rules(scene, client, lock):
    rules, providers = [], {}
    for kind, expression, target in logical_rules(scene, client):
        if kind == 'literal':
            rules.append(attach(expression, target, client))
            continue
        for resource in lock['clients'][client][expression]:
            if client == 'Clash':
                name = expression + '-' + resource['kind']
                providers[name] = {'type': 'http', 'behavior': resource['kind'], 'format': 'yaml',
                                   'url': resource['url'], 'path': './rules/' + name + '-' + lock['commit'][:12] + '.yaml', 'interval': 86400}
                rules.append(f'RULE-SET,{name},{target}' + (',no-resolve' if resource['kind'] == 'classical' else ''))
            else:
                prefix = 'DOMAIN-SET' if resource['kind'] == 'domain' else 'RULE-SET'
                rules.append(f'{prefix},{resource["url"]},{target}' + (',no-resolve' if prefix == 'RULE-SET' else ''))
    return rules, providers


def basic_groups(scene, client):
    groups = {'Guard': ['REJECT', 'DIRECT']}
    if scene == '科学上网':
        # Safe template: no fictitious endpoint and no accidental direct fallback for proxy traffic.
        groups['Proxies'] = ['PROXY'] if client == 'Shadowrocket' else ['REJECT']
        groups.update({'AI': ['Proxies'], 'Netflix': ['Proxies'], 'Apple': ['DIRECT', 'Proxies'], 'Bilibili': ['DIRECT', 'Proxies']})
    elif scene == '回国':
        groups['回国代理'] = ['DIRECT', 'PROXY'] if client == 'Shadowrocket' else ['DIRECT']
    return groups


def conf_section(name, lines):
    return '[' + name + ']\n' + '\n'.join(lines) + '\n\n'


def conf(scene, client, lock):
    lines, _ = rendered_rules(scene, client, lock)
    header = f'# {scene} | {client} | rules {lock["commit"][:12]}\n'
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
    args = parser.parse_args()
    if args.command == 'refresh':
        refresh(args.ref)
    elif args.command == 'fetch':
        hydrate(load_lock(), network=True)
    else:
        generate()


if __name__ == '__main__':
    main()
