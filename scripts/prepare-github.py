"""Export current source to a new directory, excluding private history and binaries."""
from pathlib import Path
import shutil
import sys
root = Path(__file__).resolve().parents[1]
if len(sys.argv) != 2:
    raise SystemExit('Usage: python3 scripts/prepare-github.py NEW_DIRECTORY')
destination = Path(sys.argv[1]).resolve()
if destination.exists():
    raise SystemExit('Destination must be new; existing repositories are never overwritten.')
destination.mkdir(parents=True)
folders = ['.cargo', '.github', 'assets', 'crates', 'macos', 'scripts', 'installer', 'docs']
files = ['Cargo.toml', 'Cargo.lock', 'README.md', 'LICENSE', 'SECURITY.md', 'PRIVACY.md', 'THIRD-PARTY-NOTICES.txt', '.gitignore']
for name in folders:
    shutil.copytree(root/name, destination/name, ignore=shutil.ignore_patterns('__pycache__', '.DS_Store'))
for name in files:
    shutil.copy2(root/name, destination/name)
print(f'Exported source to {destination}. Review it, then initialize a NEW Git repository.')
print('Do not copy the private working repository .git or its historical project notes.')
