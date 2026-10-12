#!/usr/bin/env python3
"""Check the explicit public source inventory and local documentation links."""
import json
from pathlib import Path
import re
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
expected = set(json.loads((ROOT / 'public-files.json').read_text())['files'])
actual = set()
for path in ROOT.rglob('*'):
    rel = path.relative_to(ROOT)
    if rel.parts[0] in {'.git', 'target'} or '.build' in rel.parts or '.swiftpm' in rel.parts:
        continue
    if path.is_symlink():
        assert str(rel) == 'AGENTS.md' and path.readlink() == Path('CLAUDE.md'), rel
    elif path.is_dir():
        continue
    else:
        assert path.is_file(), rel
        path.read_text(encoding='utf-8')
    assert rel.parts[0] not in {'apps', 'reports', 'xcode-skills', '.acp'}, rel
    actual.add(rel.as_posix())
assert actual == expected, {'extra': sorted(actual-expected), 'missing': sorted(expected-actual)}
links = 0
for name in sorted(actual):
    if not name.endswith('.md'):
        continue
    path = ROOT / name
    body = re.sub(r'```[\s\S]*?```', '', path.read_text())
    for target in re.findall(r'\]\(([^)]+)\)', body):
        if target.startswith(('https://', 'http://', 'mailto:', '#')):
            continue
        target = unquote(target.split('#', 1)[0])
        dest = (path.parent / target).resolve()
        assert not Path(target).is_absolute() and dest.is_relative_to(ROOT) and dest.exists(), (name, target)
        links += 1
print(json.dumps({'ok': True, 'files': len(actual), 'localLinks': links, 'macAppIncluded': False}, indent=2))
