"""Inspect MSI safety properties and confirm its embedded SCR matches this build."""
import csv
import hashlib
import io
from pathlib import Path
import subprocess
import tempfile
from version import VERSION, MSI_NAME
root = Path(__file__).resolve().parents[1]
msi = root/'dist'/MSI_NAME
def table(name):
    text = subprocess.check_output(['msiinfo', 'export', str(msi), name], text=True)
    lines = text.splitlines()
    return list(csv.DictReader(io.StringIO('\n'.join([lines[0], *lines[3:]])), delimiter='\t'))
props = {r['Property']: r['Value'] for r in table('Property')}
assert props['ProductVersion'] == VERSION
registry = table('Registry')
assert next(r['Value'] for r in registry if r['Name'] == 'DocsVersion') == VERSION
assert props.get('ALLUSERS') == '1', 'Must be per-machine'
assert 'x64;1033' in subprocess.check_output(['msiinfo', 'suminfo', str(msi)], text=True)
for row in table('Registry'):
    assert row['Root'] == '2', 'Only HKLM writes are allowed'
    assert row['Key'] == 'Software\\Ibert Consulting\\ThreatAtlas', 'Unexpected registry write'
components = table('Component')
for row in components:
    assert int(row['Attributes']) & 256, 'Expected 64-bit components'
saver = next(r for r in table('File') if r['File'] == 'ScreenSaver')
home = next(r for r in components if r['Component'] == saver['Component_'])
assert home['Directory_'] == 'System64Folder', 'SCR must install to native System32'
assert not any(r['Directory_'] == 'SystemFolder' for r in components), 'No 32-bit system directory copy'
assert saver['FileName'].endswith('ThreatAtlas.scr')
assert any('PERUSERINSTALL' in r['Condition'] for r in table('LaunchCondition')), 'Must refuse over a per-user install'
shortcuts = table('Shortcut')
assert len(shortcuts) == 3
assert any(r['Target'] == '[#ScreenSaver]' and r['Arguments'] == '--windowed' for r in shortcuts)
seq = {r['Action']: int(r['Sequence']) for r in table('InstallExecuteSequence')}
assert seq['InstallInitialize'] < seq['RemoveExistingProducts'] < seq['InstallFiles'], 'Upgrade must allow rollback'
tables = subprocess.check_output(['msiinfo', 'tables', str(msi)], text=True).splitlines()
assert 'CustomAction' not in tables or not table('CustomAction'), 'Installer must not execute custom code'
with tempfile.TemporaryDirectory(prefix='threatatlas-msi-') as folder:
    subprocess.run(['msiextract', '-C', folder, str(msi)], check=True, capture_output=True)
    files = list(Path(folder).rglob('ThreatAtlas.scr'))
    assert len(files) == 1
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    assert digest(files[0]) == digest(root/'dist/ThreatAtlas.scr'), 'Wrong/stale binary embedded'
print('MSI architecture, scope, registry, shortcuts, upgrade rollback and embedded binary passed.')
