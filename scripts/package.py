from pathlib import Path
import zipfile
import subprocess
import tempfile
import sys
import plistlib
from version import VERSION, BUILD, TAG
root=Path(__file__).resolve().parents[1]
out=root.parent
subprocess.run([sys.executable, str(root/'scripts/version.py'), '--check'], check=True)
def pack(name,files):
 with zipfile.ZipFile(out/name,'w',zipfile.ZIP_DEFLATED) as z:
  for path,arc in files:
   if path.is_file() and path.name!='.DS_Store':z.write(path,arc)
 with zipfile.ZipFile(out/name) as z:assert z.testzip() is None
common=[(root/n,n) for n in ['README.md','LICENSE','SECURITY.md','PRIVACY.md','THIRD-PARTY-NOTICES.txt','version.json']]+[(p,'licenses/'+p.name) for p in (root/'assets').glob('*.md')]+[(root/'assets/FONT-LICENSE.txt','licenses/FONT-LICENSE.txt')]
mac=[]
for n in ['ThreatAtlasSOC.saver','Threat Atlas SOC.app']:
 mac += [(p,p.relative_to(root/'dist')) for p in (root/'dist'/n).rglob('*') if p.is_file()]
# Keep the stable updater asset name; legal notices are inside the signed app.
if mac:
 for name in ['ThreatAtlasSOC.saver','Threat Atlas SOC.app']:
  info=plistlib.loads((root/'dist'/name/'Contents/Info.plist').read_bytes())
  if info.get('CFBundleShortVersionString') != VERSION or info.get('CFBundleVersion') != str(BUILD):
   raise SystemExit('Refusing to package stale macOS bundles; rebuild from this release source.')
 pack('ThreatAtlas-macOS.zip',mac)
if (root/'dist/ThreatAtlas.scr').exists():pack(f'ThreatAtlas-Windows-{TAG}.zip',[(root/'dist/ThreatAtlas.scr','ThreatAtlas.scr')]+common)
# The source release must use the same sanitized allowlist as the GitHub export.
with tempfile.TemporaryDirectory(prefix='threatatlas-source-') as temporary:
 source=Path(temporary)/'ThreatAtlas'
 subprocess.run([sys.executable,str(root/'scripts/prepare-github.py'),str(source)],check=True)
 pack(f'ThreatAtlas-source-{TAG}.zip',[(p,Path('ThreatAtlas')/p.relative_to(source)) for p in source.rglob('*') if p.is_file()])
