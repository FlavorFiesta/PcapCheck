"""Public source checks must reject staged secrets even after worktree cleanup."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools import check_public_source as checker


def test_public_scan_rejects_realistic_key_without_echoing_value(capsys):
    key = 'sk-' + 'A1b2C3d4' * 5
    findings = checker.inspect_blob('module.py', f'key = "{key}"'.encode())
    assert 'API key pattern' in findings
    assert all(key not in reason for reason in findings)


def test_public_scan_rejects_private_material():
    for name in ('backend/data/settings.json', 'tests/captures/customer.pcap', 'snapshot.db', '.env'):
        assert checker.inspect_blob(name, b'{}'), name
    assert not checker.inspect_blob('packaging/portable-data/settings.json', b'{"llm":{"api_key":""}}')
    assert not checker.inspect_blob('frontend/scripts/smoke-run.cjs', b'// test source')


def test_public_scan_checks_git_index_even_if_worktree_is_clean(tmp_path, monkeypatch, capsys):
    if not shutil.which('git'):
        pytest.skip('Git is needed for index checks')
    subprocess.run(['git', 'init', '-b', 'main', str(tmp_path)], check=True, capture_output=True)
    path = tmp_path / 'sample.py'
    key = 'sk-' + 'z9Y8x7W6' * 5
    path.write_text(f'key = "{key}"\n', encoding='utf-8')
    subprocess.run(['git', '-C', str(tmp_path), 'add', 'sample.py'], check=True, capture_output=True)
    path.write_text('key = ""\n', encoding='utf-8')
    monkeypatch.setattr(checker, 'ROOT', tmp_path)
    assert checker.main() == 1
    output = capsys.readouterr().out
    assert '(index)' in output
    assert key not in output
