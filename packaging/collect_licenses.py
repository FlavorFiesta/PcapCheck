"""Collect notices for the Python runtime and runtime dependency closure."""
from __future__ import annotations

import argparse
import importlib.metadata as metadata
import json
import shutil
import sys
from collections import deque
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_REQUIREMENTS = ['fastapi', 'uvicorn[standard]', 'pydantic',
                        'python-multipart', 'tkinterdnd2', 'pyinstaller']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    queue = deque(Requirement(value) for value in RUNTIME_REQUIREMENTS)
    visited = set()
    inventory = {}
    while queue:
        requirement = queue.popleft()
        key = (requirement.name.casefold(), tuple(sorted(requirement.extras)))
        if key in visited:
            continue
        visited.add(key)
        distribution = metadata.distribution(requirement.name)
        name = distribution.metadata['Name']
        if name not in inventory:
            target = output / 'python-packages' / name
            notices = []
            for file in distribution.files or []:
                if not any(word in file.name.casefold() for word in ('license', 'copying', 'notice')):
                    continue
                source = Path(distribution.locate_file(file))
                if not source.is_file() or source.suffix in {'.py', '.pyc'}:
                    continue
                relative = Path(*[part for part in file.parts if part not in ('..', '.')])
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                notices.append(destination.relative_to(output).as_posix())
            if not notices:
                raise RuntimeError(f'No license files found for {name}; collect and review before distributing')
            inventory[name] = {'version': distribution.version,
                               'license': distribution.metadata.get('License-Expression') or 'See bundled notices',
                               'notices': notices}
        for raw in distribution.requires or []:
            dependency = Requirement(raw)
            if dependency.marker is None or any(dependency.marker.evaluate({'extra': extra})
                                                 for extra in {'', *requirement.extras}):
                queue.append(dependency)
    python_notices = [Path(sys.base_prefix) / 'LICENSE.txt', Path(sys.base_prefix) / 'LICENSE_PYTHON.txt']
    python_source = next((path for path in python_notices if path.is_file()), None)
    if python_source is None:
        raise RuntimeError('Python runtime license not found')
    python_target = output / 'python-runtime'
    python_target.mkdir(exist_ok=True)
    shutil.copy2(python_source, python_target / 'LICENSE.txt')
    native_licenses = ROOT / 'packaging' / 'runtime-licenses'
    if not (native_licenses / 'SOURCES.json').is_file():
        raise RuntimeError('Reviewed native runtime notices missing')
    shutil.copytree(native_licenses, output / 'native-runtime', dirs_exist_ok=True)
    inventory['Python'] = {'version': sys.version.split()[0], 'license': 'PSF-2.0',
                           'notices': ['python-runtime/LICENSE.txt']}
    (output / 'DEPENDENCIES.json').write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f'Collected license notices for {len(inventory)} Python components and native runtime libraries')


if __name__ == '__main__':
    main()
