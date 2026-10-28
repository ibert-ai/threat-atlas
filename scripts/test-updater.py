"""Offline macOS updater tests. Never enable scheduling or perform an installation."""
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
helper = str(Path(sys.argv[1]).resolve())
subprocess.run([helper, '--self-test'], check=True)
with tempfile.TemporaryDirectory(prefix='threatatlas-updater-test-') as folder:
    folder = Path(folder)
    fixtures = [
        ('valid', [('ThreatAtlasSOC.saver/Contents/Info.plist', b'plist', False)], True),
        ('traversal', [('ThreatAtlasSOC.saver/../../escape', b'bad', False)], False),
        ('absolute', [('/tmp/escape', b'bad', False)], False),
        ('extra-root', [('surprise.app/code', b'bad', False)], False),
        ('symlink', [('ThreatAtlasSOC.saver/link', b'/tmp', True)], False),
    ]
    for name, entries, accepted in fixtures:
        archive = folder / f'{name}.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for path, content, link in entries:
                item = zipfile.ZipInfo(path)
                item.create_system = 3
                item.external_attr = (0o120777 if link else 0o100644) << 16
                z.writestr(item, content)
        result = subprocess.run([helper, '--inspect-archive', str(archive)], capture_output=True)
        assert (result.returncode == 0) == accepted, (name, result.stderr)
print('Updater archive traversal, root, symlink and valid-archive tests passed.')
