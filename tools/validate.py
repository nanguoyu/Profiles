"""Validate generated routing, pinned resources for publication.

This is an offline regression check, not a proxy reachability or geolocation test.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import urllib.parse
import yaml
import profiles


def read_conf(path):
    sections = {}
    current = None
    for line in path.read_text().splitlines():
        if line.startswith('[') and line.endswith(']'):
            current = line[1:-1]
            sections[current] = []
        elif current:
            sections[current].append(line)
    return sections


def active(lines):
    return [x.strip() for x in lines if x.strip() and not x.lstrip().startswith(('#', '//', ';'))]


def split_proxy(line):
    name, value = map(str.strip, line.split('=', 1))
    return name, [x.strip() for x in next(csv.reader([value], skipinitialspace=True))]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_profile(path, client):
    if client == 'Clash':
        data = yaml.safe_load(path.read_text())
        groups = {g['name']: g['proxies'] for g in data['proxy-groups']}
        require(len(groups) == len(data['proxy-groups']), 'Duplicate group')
        return data['rules'], groups, {p['name'] for p in data['proxies']}, data
    data = read_conf(path)
    groups = {}
    for line in active(data['Proxy Group']):
        name, parts = split_proxy(line)
        require(name not in groups, 'Duplicate group')
        groups[name] = [x for x in parts[1:] if '=' not in x]
    nodes = {split_proxy(x)[0] for x in active(data.get('Proxy', []))}
    return active(data['Rule']), groups, nodes, data


def matches(expression, domain, ip):
    parts = expression.split(',')
    kind = parts[0]
    value = parts[1] if len(parts) > 1 else ''
    if kind in ('FINAL', 'MATCH'):
        return True
    if kind == 'DOMAIN':
        return domain == value
    if kind == 'DOMAIN-SUFFIX':
        return domain == value or domain.endswith('.' + value)
    if kind == 'DOMAIN-KEYWORD':
        return value in domain
    if kind in ('IP-CIDR', 'IP-CIDR6'):
        return bool(ip and ipaddress.ip_address(ip) in ipaddress.ip_network(value, strict=False))
    # GEOIP/process/UA rules need runtime context, absent from these domain/IP fixtures.
    return False


def target(rule):
    parts = rule.split(',')
    return parts[-2] if parts[-1] == 'no-resolve' else parts[-1]


def routing(rules, client, resources, domain='', ip=None):
    for rule in rules:
        parts = rule.split(',')
        if parts[0] in ('RULE-SET', 'DOMAIN-SET'):
            kind, payload = resources[parts[1]]
            if kind == 'domain':
                for entry in payload:
                    if entry.startswith('+.'):
                        expression = 'DOMAIN-SUFFIX,' + entry[2:]
                    elif entry.startswith('.'):
                        expression = 'DOMAIN-SUFFIX,' + entry[1:]
                    else:
                        expression = 'DOMAIN,' + entry
                    if matches(expression, domain, ip):
                        return target(rule)
            elif any(matches(entry, domain, ip) for entry in payload):
                return target(rule)
        elif matches(rule, domain, ip):
            return target(rule)
    raise ValueError('No final rule')


def verify_groups(groups, nodes):
    builtin = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PROXY'}
    require(not (set(groups) & nodes), 'Node/group name collision')
    def walk(name, seen):
        require(name not in seen, 'Cyclic group dependency')
        require(bool(groups[name]), 'Empty group')
        for member in groups[name]:
            require(member in builtin | nodes | set(groups), 'Unknown policy reference')
            if member in groups:
                walk(member, seen | {name})
    for name in groups:
        walk(name, set())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mihomo', type=Path)
    parser.add_argument('--mmdb', type=Path)
    args = parser.parse_args()
    lock = profiles.load_lock()
    profiles.hydrate(lock)
    resources = {}
    for client, categories in lock['clients'].items():
        resources[client] = {}
        for category, parts in categories.items():
            if category in ('AdvertisingLite', 'Privacy', 'China', 'Apple'):
                require(any(r['kind'] == 'domain' for r in parts), 'Missing split domain source')
            for r in parts:
                require('/' + lock['commit'] + '/' in r['url'], 'Unpinned source')
                payload = profiles.entries((profiles.CACHE / lock['commit'] / r['key']).read_bytes(), r['kind'], client)
                require(len(payload) == r['entries'], 'Source count changed')
                key = category + '-' + r['kind'] if client == 'Clash' else r['url']
                resources[client][key] = (r['kind'], payload)
    roots = [profiles.ROOT]
    cases = {
        '科学上网': [('chatgpt.com', 'AI'), ('api.openai.com', 'AI'), ('claude.ai', 'AI'), ('github.com', 'Proxies'), ('www.google.com', 'Proxies'), ('www.bilibili.com', 'Bilibili'), ('captive.apple.com', 'DIRECT'), ('example.invalid', 'Proxies')],
        '回国': [('www.bilibili.com', '回国代理'), ('www.google.com', 'DIRECT'), ('paypal.com', 'DIRECT'), ('chatgpt.com', 'DIRECT'), ('example.invalid', 'DIRECT')],
        '只过滤不代理': [('www.google.com', 'DIRECT'), ('github.com', 'DIRECT'), ('example.invalid', 'DIRECT')],
    }
    count = checks = native = 0
    for root in roots:
        for client in profiles.CLIENTS:
            for scene in profiles.POLICY['scenes']:
                name = profiles.PROFILE_NAMES[scene] + ('.yaml' if client == 'Clash' else '.conf')
                path = root / client / name
                rules, groups, nodes, data = read_profile(path, client)
                verify_groups(groups, nodes)
                require(rules[-1].split(',')[0] in ('FINAL', 'MATCH'), 'Missing terminal rule')
                require(sum(r.startswith(('FINAL,', 'MATCH,')) for r in rules) == 1, 'Unreachable rules after final')
                require(all(target(r) in set(groups) | nodes | {'DIRECT', 'REJECT'} for r in rules), 'Undefined rule policy')
                require('policy-path=' not in path.read_text() and 'proxy-providers:' not in path.read_text(), 'Retired subscriptions remain')
                if scene == '回国':
                    require(groups['回国代理'][0] == 'DIRECT', 'Unconfirmed return node selected automatically')
                for domain, expected in cases[scene]:
                    actual = routing(rules, client, resources[client], domain=domain)
                    require(actual == expected, f'{client}/{scene}: {domain} routed to {actual}, expected {expected}')
                    checks += 1
                for ip in ('100.100.100.100', '192.168.10.2', 'fd7a:115c:a1e0::1'):
                    require(routing(rules, client, resources[client], ip=ip) == 'DIRECT', 'Private network incorrectly proxied')
                    checks += 1
                if client == 'Clash':
                    require(not ({'tun', 'external-controller', 'allow-lan', 'mixed-port', 'port', 'socks-port'} & set(data)), 'Desktop/listener settings in shared Apple profile')
                    if args.mihomo:
                        home = profiles.ROOT / '.cache' / 'validation'
                        home.mkdir(parents=True, exist_ok=True)
                        if args.mmdb:
                            profiles.atomic(home / 'Country.mmdb', args.mmdb.read_bytes())
                        for provider in data['rule-providers'].values():
                            r = next(r for parts in lock['clients']['Clash'].values() for r in parts if r['url'] == provider['url'])
                            profiles.atomic(home / provider['path'], (profiles.CACHE / lock['commit'] / r['key']).read_bytes())
                        run = subprocess.run([str(args.mihomo.resolve()), '-t', '-d', str(home), '-f', str(path)], capture_output=True, text=True, timeout=60)
                        # Raw errors can contain private proxy fields; save only locally on failure.
                        if run.returncode:
                            profiles.atomic(profiles.ROOT / '.cache' / 'validation-error.log', run.stdout + run.stderr)
                            raise ValueError('Mihomo validation failed; details in .cache/validation-error.log')
                        native += 1
                count += 1
    optional_checks = 0
    for client in profiles.CLIENTS:
        for name, samples in {
            'Outbound': [('www.zhihu.com', True), ('github.com', False)],
            'FilterOnly': [('www.baidu.com', True), ('gitlab.com', True), ('sns-video-hw.xhscdn.com', True), ('github.com', False)],
        }.items():
            extension = '.yaml' if client == 'Clash' else '.list'
            path = profiles.ROOT / 'Custom' / 'Blocklists' / client / (name + extension)
            payload = profiles.entries(path.read_bytes(), 'classical', client)
            for domain, expected in samples:
                actual = any(matches(rule, domain, None) for rule in payload)
                require(actual == expected, 'Optional blocklist scope regression')
                optional_checks += 1
    result = {'profiles': count, 'routing_assertions': checks, 'mihomo_native_checks': native, 'source_resources': sum(len(x) for x in resources.values()), 'optional_blocklist_assertions': optional_checks, 'result': 'passed'}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
