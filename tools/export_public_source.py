"""Export an allowlisted, data-free source tree; never copy Git history."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    '.gitignore', '.gitattributes', 'LICENSE', 'README.md', 'CONTRIBUTING.md',
    'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'pytest.ini', 'start.bat', 'start_desktop.bat',
    'backend/requirements.txt', 'backend/requirements-build.txt',
    'frontend/.gitignore', 'frontend/package.json', 'frontend/package-lock.json',
    'frontend/index.html', 'frontend/tsconfig.json', 'frontend/vite.config.ts',
    'frontend/scripts/smoke.tsx', 'frontend/scripts/smoke-run.cjs',
    'packaging/PcapCheck.iss', 'packaging/backend_service.py',
    'packaging/build_windows.ps1', 'packaging/collect_licenses.py', 'packaging/pcapcheck.ico',
    'packaging/languages/ChineseSimplified.isl', 'packaging/languages/LICENSE.txt',
    'packaging/portable-data/settings.json', 'packaging/portable-data/README.txt',
    'tools/verify_kb.py', 'tools/review_checks.py', 'tools/gen_synthetic.py',
    'tools/check_public_source.py', 'tools/export_public_source.py',
    'docs/GETTING_STARTED.md', 'docs/TESTING.md', 'docs/RELEASING.md', 'docs/GITHUB_PUBLISH.md',
]
TREES = {'backend/app': {'.py'}, 'desktop_gui': {'.py'},
         'frontend/src': {'.ts', '.tsx', '.css', '.svg'},
         'docs/kb': {'.md'}, '.github': {'.yml', '.yaml', '.md'},
         'packaging/runtime-licenses': {'.txt', '.json'}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='Optional new source ZIP, without dependencies or Git history')
    args = parser.parse_args()
    destination = args.output.resolve()
    if destination.exists() or destination == ROOT or ROOT.is_relative_to(destination):
        parser.error('Output must be a new directory and cannot contain the source root')
    archive = args.archive.resolve() if args.archive else None
    if archive and (archive.exists() or archive.suffix.lower() != '.zip' or archive.is_relative_to(destination)):
        parser.error('Archive must be a new .zip outside the exported source directory')
    selected = {Path(name) for name in FILES}
    for directory, suffixes in TREES.items():
        selected.update(path.relative_to(ROOT) for path in (ROOT / directory).rglob('*')
                        if path.is_file() and path.suffix.lower() in suffixes
                        and '__pycache__' not in path.parts)
    selected.update(path.relative_to(ROOT) for path in (ROOT / 'backend/tests').glob('test_*.py'))
    selected.update(Path('backend/tests') / name for name in ('conftest.py', 'pcapcraft.py'))
    from check_public_source import inspect_blob
    manifest = {}
    for relative in sorted(selected):
        source = ROOT / relative
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(ROOT):
            raise RuntimeError(f'Missing or unsafe source: {relative}')
        data = source.read_bytes()
        problems = inspect_blob(relative.as_posix(), data)
        if problems:
            raise RuntimeError(f'Blocked source {relative}: {", ".join(problems)}')
        manifest[relative.as_posix()] = hashlib.sha256(data).hexdigest()
    destination.mkdir(parents=True)
    for relative in sorted(selected):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    (destination / 'SOURCE_MANIFEST.json').write_text(
        json.dumps({'files': manifest}, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    subprocess.run([sys.executable, str(destination / 'tools/check_public_source.py')], check=True)
    if archive:
        archive.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
            for relative in sorted(selected | {Path('SOURCE_MANIFEST.json')}):
                bundle.write(destination / relative, 'PcapCheck/' + relative.as_posix())
        print(f'Source archive: {archive}')
    print(f'Exported {len(selected)} reviewed source files to {destination}')


if __name__ == '__main__':
    main()
