from pathlib import Path
import zipfile
import subprocess
import tempfile
import sys
root=Path(__file__).resolve().parents[1]
out=root.parent
def pack(name,files):
 with zipfile.ZipFile(out/name,'w',zipfile.ZIP_DEFLATED) as z:
  for path,arc in files:
   if path.is_file() and path.name!='.DS_Store':z.write(path,arc)
 with zipfile.ZipFile(out/name) as z:assert z.testzip() is None
common=[(root/n,n) for n in ['README.md','LICENSE','SECURITY.md','PRIVACY.md','THIRD-PARTY-NOTICES.txt']]+[(p,'licenses/'+p.name) for p in (root/'assets').glob('*.md')]+[(root/'assets/FONT-LICENSE.txt','licenses/FONT-LICENSE.txt')]
mac=[]
for n in ['ThreatAtlasSOC.saver','Threat Atlas SOC.app']:
 mac += [(p,p.relative_to(root/'dist')) for p in (root/'dist'/n).rglob('*') if p.is_file()]
if mac:pack('ThreatAtlas-macOS-v0.3.0.zip',mac+common)
if (root/'dist/ThreatAtlas.scr').exists():pack('ThreatAtlas-Windows-v0.3.0.zip',[(root/'dist/ThreatAtlas.scr','ThreatAtlas.scr')]+common)
# The source release must use the same sanitized allowlist as the GitHub export.
with tempfile.TemporaryDirectory(prefix='threatatlas-source-') as temporary:
 source=Path(temporary)/'ThreatAtlas'
 subprocess.run([sys.executable,str(root/'scripts/prepare-github.py'),str(source)],check=True)
 pack('ThreatAtlas-source-v0.3.0.zip',[(p,Path('ThreatAtlas')/p.relative_to(source)) for p in source.rglob('*') if p.is_file()])
