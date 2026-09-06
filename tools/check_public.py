"""Check changed or staged publication files for private artifacts and credentials.

This guard catches common accidental disclosures; it does not replace diff review.
It reads only Git-visible publication candidates, never external/private files.
"""
import argparse
from pathlib import Path
import re
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staged', action='store_true')
    args = parser.parse_args()
    if args.staged:
        paths = set(git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z').decode().split('\0'))
    else:
        paths = set(git('diff', 'HEAD', '--name-only', '--diff-filter=ACMR', '-z').decode().split('\0'))
        paths |= set(git('ls-files', '--others', '--exclude-standard', '-z').decode().split('\0'))
    paths.discard('')
    patterns = {
        'device home path': r'/(?:Users|home)/[^/\s]+/',
        'proxy import URI': r'(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2)://[^\s]+',
        'private key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        'GitHub token': r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b',
        'credential declaration': r'(?im)^\s*(?:password|psk|ca-p12|ca-passphrase|external-controller-password)\s*[:=]\s*\S+',
        'subscription token': r'https?://[^\s]+[?&](?:token|access_token|auth_key)=[^\s&]+',
        'authenticated controller': r'(?im)^\s*(?:http-api|external-controller)\s*[:=]\s*[^\s@]+@',
    }
    failures = []
    for name in sorted(paths):
        path = Path(name)
        if any(part in {'.private', '.cache', '.venv', 'local', '__pycache__'} for part in path.parts) or path.suffix in {'.p12', '.pfx', '.key', '.zip'} or path.name.startswith('.env') or '节点导入' in name:
            failures.append((name, 'private artifact path'))
            continue
        if args.staged:
            raw = git('show', ':' + name)
        else:
            if (ROOT / name).is_symlink():
                failures.append((name, 'symlink is not a publication file'))
                continue
            raw = (ROOT / name).read_bytes()
        try:
            content = raw.decode('utf-8')
        except UnicodeDecodeError:
            failures.append((name, 'unexpected non-text file'))
            continue
        for reason, pattern in patterns.items():
            if re.search(pattern, content):
                failures.append((name, reason))
        if path.parent == Path('Clash') and path.suffix == '.yaml':
            data = yaml.safe_load(content)
            if data.get('proxies') or data.get('proxy-providers'):
                failures.append((name, 'public template contains nodes or subscriptions'))
        if path.parent in {Path('Surge'), Path('Shadowrocket')} and path.suffix == '.conf':
            if re.search(r'^\[(?:Proxy|MITM|Ponte)\]$', content, re.M) or 'policy-path=' in content:
                failures.append((name, 'public template contains private configuration sections'))
    if failures:
        for name, reason in failures:
            print(name + ': ' + reason)
        raise SystemExit(1)
    print('Publication check passed for', len(paths), 'staged' if args.staged else 'changed/new', 'text files.')


if __name__ == '__main__':
    main()
