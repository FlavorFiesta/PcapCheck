"""Check public source candidates and the Git index without printing secrets."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', '.venv', 'node_modules', '__pycache__', '.pytest_cache',
             'dist', 'build', 'opensource'}
DENIED_DIRS = {'data', 'uploads', '_backups', '测试包', 'captures',
               'captures_synthetic', 'ui_shots', 'gui_eval'}
DENIED_SUFFIXES = {'.pcap', '.pcapng', '.cap', '.db', '.sqlite', '.sqlite3',
                   '.log', '.exe', '.dll', '.msi', '.zip', '.pem', '.key', '.pfx', '.p12'}
INTERNAL = {'背景.md', '方案.md', '记忆.md', '进展.md', 'progress.html', 'llm_probe.py'}
PATTERNS = {
    'API key pattern': re.compile(r'\bsk-[A-Za-z0-9_-]{20,}'),
    'GitHub token pattern': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})'),
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'credentials embedded in URL': re.compile(r'https?://[^\s/:]+:[^\s/@]+@'),
    'personal Windows home path': re.compile(r'[A-Za-z]:[\\/]+Users[\\/]+(?!Public\b|Default\b)[A-Za-z0-9_.-]+'),
}


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True, check=False)


def inspect_blob(name: str, data: bytes) -> list[str]:
    path = Path(name)
    problems = []
    if any(p in DENIED_DIRS for p in path.parts) or path.name in INTERNAL:
        problems.append('private/runtime material')
    if path.suffix.lower() in DENIED_SUFFIXES or name.lower().endswith(('.pcap.gz', '.pcapng.gz')):
        problems.append('capture, database, credential or binary artifact')
    if path.name.startswith('.env') and path.name != '.env.example':
        problems.append('environment credentials file')
    if name.startswith(('packaging/smoke-', 'packaging/output/')):
        problems.append('generated release/test material')
    if len(data) > 2 * 1024 * 1024:
        problems.append('unexpected source file over 2 MiB')
    if b'\x00' not in data:
        text = data.decode('utf-8', errors='replace')
        for label, pattern in PATTERNS.items():
            if pattern.search(text):
                problems.append(label)
        if path.name == 'settings.json':
            try:
                settings = json.loads(text)
                if settings.get('llm', {}).get('api_key'):
                    problems.append('non-empty API key in settings')
            except (ValueError, AttributeError):
                problems.append('invalid settings template')
    return problems


def main() -> int:
    errors = []
    checked = 0
    try:
        probe = git('rev-parse', '--show-toplevel')
    except FileNotFoundError:
        probe = None
    is_repo = (probe is not None and probe.returncode == 0 and
               Path(probe.stdout.decode().strip()).resolve() == ROOT.resolve())
    if is_repo:
        listing = git('ls-files', '--cached', '--others', '--exclude-standard', '-z')
        if listing.returncode:
            raise RuntimeError('Cannot enumerate Git candidates')
        names = sorted(set(n.decode('utf-8') for n in listing.stdout.split(b'\0') if n))
    else:
        names = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*')
                       if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts))
    if not names:
        print('FAIL: no public source candidates found')
        return 1
    for name in names:
        path = ROOT / name
        if path.is_symlink():
            errors.append(f'{name}: symbolic links require manual review')
            continue
        if path.is_file():
            checked += 1
            errors.extend(f'{name}: {reason}' for reason in inspect_blob(name, path.read_bytes()))
        if is_repo:
            # Examine staged bytes too: a clean working copy does not clear a secret already staged.
            staged = git('show', ':' + name)
            if staged.returncode == 0:
                errors.extend(f'{name} (index): {reason}' for reason in inspect_blob(name, staged.stdout))
    for error in sorted(set(errors)):
        print('FAIL:', error)  # File names and finding labels only; never print matched values.
    if errors:
        return 1
    print(f'PASS: {checked} public source candidates; no blocked artifacts or known secret patterns')
    return 0


if __name__ == '__main__':
    sys.exit(main())
