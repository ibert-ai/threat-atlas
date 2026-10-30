"""Collect license notices for dependencies resolved on the supported targets."""
import json
from pathlib import Path
import subprocess
root = Path(__file__).resolve().parents[1]
packages = {}
for target in ['aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc', 'x86_64-unknown-linux-gnu']:
    data = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version', '1', '--filter-platform', target], cwd=root))
    resolved = {node['id'] for node in data['resolve']['nodes']}
    for package in data['packages']:
        if package['id'] in resolved and package['source']:
            packages[(package['name'], package['version'])] = package
text = ['# Third-party Rust dependency notices', 'Generated for macOS arm64/x64, Windows x64 and the Linux x64 preview. Bundled font/map notices are in assets/.\n']
for (name, version), package in sorted(packages.items()):
    text.append(f'\n## {name} {version}\nLicense: {package["license"] or "See crate license"}\n')
    directory = Path(package['manifest_path']).parent
    notices = sorted(p for p in directory.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'COPYRIGHT')))
    for p in notices:
        text.append(f'\n### {p.name}\n\n{p.read_text(errors="replace")}\n')
    if not notices:
        text.append(f'License text not present at crate root; review https://crates.io/crates/{name}/{version} before redistribution.\n')
(root/'THIRD-PARTY-NOTICES.txt').write_text('\n'.join(line.rstrip() for line in '\n'.join(text).splitlines()) + '\n')
print(f'Collected notices for {len(packages)} resolved dependencies.')
