"""Exercise a release bump and reject stale/invalid platform metadata offline."""
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='threatatlas-versions-') as folder:
    stage = Path(folder)
    for name in ('version.json', 'Cargo.toml', 'Cargo.lock', 'crates/core/Cargo.toml',
                 'crates/windows/Cargo.toml', 'macos/Info.plist', 'installer/ThreatAtlas.wxs', 'scripts/version.py'):
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    def run(*args, succeeds=True):
        result = subprocess.run([sys.executable, str(stage/'scripts/version.py'), *args], capture_output=True, text=True)
        assert (result.returncode == 0) == succeeds, result.stdout + result.stderr
        return result.stdout.strip()
    run('--check')
    manifest = json.loads((stage/'version.json').read_text())
    manifest.update(version='0.4.1', build=8, prerelease='rc.2')
    (stage/'version.json').write_text(json.dumps(manifest))
    run('--check', succeeds=False)
    run('--write')
    run('--check')
    run('--write')
    run('--check')
    assert run('--tag') == 'v0.4.1-rc.2'
    assert run('--msi-name') == 'ThreatAtlas-0.4.1-x64.msi'
    info = plistlib.loads((stage/'macos/Info.plist').read_bytes())
    assert (info['CFBundleShortVersionString'], info['CFBundleVersion']) == ('0.4.1', '8')
    assert 'Name="DocsVersion" Value="0.4.1"' in (stage/'installer/ThreatAtlas.wxs').read_text()
    manifest['prerelease'] = None
    (stage/'version.json').write_text(json.dumps(manifest))
    assert run('--tag') == 'v0.4.1'
    for key, value in [('version', '256.0.0'), ('version', '1.0.0-rc.1'), ('build', 0), ('prerelease', 'beta')]:
        invalid = dict(manifest); invalid[key] = value
        (stage/'version.json').write_text(json.dumps(invalid))
        run('--check', succeeds=False)
print('Release bump, drift rejection, idempotence, stable/preview tags and MSI bounds passed.')
