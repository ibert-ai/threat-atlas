"""Read the release manifest and keep checked-in platform metadata synchronized."""
import argparse
import json
from pathlib import Path
import plistlib
import re

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / 'version.json').read_text())
VERSION = manifest['version']
BUILD = manifest['build']
PRERELEASE = manifest['prerelease']
if not isinstance(VERSION, str) or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', VERSION):
    raise ValueError('Version must be canonical major.minor.patch')
if any(n > maximum for n, maximum in zip(map(int, VERSION.split('.')), (255, 255, 65535))):
    raise ValueError('Version exceeds Windows MSI limits')
if type(BUILD) is not int or not 1 <= BUILD <= 2147483647:
    raise ValueError('Build must be a positive integer')
if PRERELEASE is not None and (not isinstance(PRERELEASE, str) or not re.fullmatch(r'rc\.[1-9][0-9]*', PRERELEASE)):
    raise ValueError('Prerelease must be rc.N or null for stable')
TAG = 'v' + VERSION + ('-' + PRERELEASE if PRERELEASE else '')
MSI_NAME = 'ThreatAtlas-' + VERSION + '-x64.msi'

def generated():
    cargo = (ROOT / 'Cargo.toml').read_text()
    cargo = re.sub(r'\n\[workspace.package\]\nversion = "[^"]+"\n+', '\n', cargo)
    cargo = cargo.replace('[profile.release]', '[workspace.package]\nversion = "' + VERSION + '"\n\n[profile.release]')
    yield ROOT / 'Cargo.toml', cargo.encode()
    lock = (ROOT / 'Cargo.lock').read_text()
    for name in ('threat-atlas', 'threat-atlas-core'):
        lock, count = re.subn(r'(\[\[package\]\]\nname = "' + name + r'"\nversion = ")[^"]+', r'\g<1>' + VERSION, lock)
        if count != 1: raise ValueError('Missing workspace lockfile entry: ' + name)
        path = ROOT / 'crates' / ('windows' if name == 'threat-atlas' else 'core') / 'Cargo.toml'
        member = re.sub(r'^version = "[^"]+"$', 'version.workspace = true', path.read_text(), flags=re.M)
        if 'version.workspace = true' not in member: raise ValueError('Missing inherited package version')
        yield path, member.encode()
    yield ROOT / 'Cargo.lock', lock.encode()
    path = ROOT / 'macos/Info.plist'
    info = plistlib.loads(path.read_bytes())
    info['CFBundleShortVersionString'] = VERSION
    info['CFBundleVersion'] = str(BUILD)
    yield path, plistlib.dumps(info, sort_keys=False)
    path = ROOT / 'installer/ThreatAtlas.wxs'
    wix = re.sub(r'(<Product\b[^>]*\bVersion=")[^"]+', r'\g<1>' + VERSION, path.read_text())
    wix = re.sub(r'(Name="DocsVersion" Value=")[^"]+', r'\g<1>' + VERSION, wix)
    yield path, wix.encode()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    flags = parser.add_mutually_exclusive_group()
    for option in ('write', 'check', 'version', 'build', 'tag', 'msi-name'):
        flags.add_argument('--' + option, action='store_true')
    args = parser.parse_args()
    for flag, value in [('version', VERSION), ('build', BUILD), ('tag', TAG), ('msi_name', MSI_NAME)]:
        if getattr(args, flag): print(value); return
    stale = []
    for path, expected in generated():
        if path.read_bytes() != expected:
            stale.append(str(path.relative_to(ROOT)))
            if args.write: path.write_bytes(expected)
    if stale and not args.write: parser.exit(1, 'Stale version metadata: ' + ', '.join(stale) + '\nRun python3 scripts/version.py --write\n')
    print(('Synchronized ' if args.write else 'Checked ') + TAG + ', build ' + str(BUILD))
if __name__ == '__main__': main()
