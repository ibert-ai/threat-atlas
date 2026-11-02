"""Check direct workspace registry dependencies for newer stable releases."""
import json,re,subprocess,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def check():
    m=json.loads(subprocess.check_output(['cargo','metadata','--no-deps','--locked','--format-version','1'],cwd=ROOT,text=True))
    names=sorted(set(d['name'] for p in m['packages'] for d in p['dependencies'] if d.get('source','') and d['source'].startswith('registry+')))
    locked={}
    for block in (ROOT/'Cargo.lock').read_text().split('[[package]]')[1:]:
        n=re.search(r'^name = "([^"]+)"',block,re.M);v=re.search(r'^version = "([^"]+)"',block,re.M)
        if n and v:locked.setdefault(n[1],set()).add(v[1])
    result=[]
    for name in names:
        req=urllib.request.Request('https://crates.io/api/v1/crates/'+name,headers={'User-Agent':'ThreatAtlas-security-sanity/1 (https://github.com/ibert-ai/threat-atlas)'})
        with urllib.request.urlopen(req,timeout=20) as response:data=json.load(response)
        latest=data['crate'].get('max_stable_version')
        if not latest:raise RuntimeError('No stable version metadata for '+name)
        versions=sorted(locked.get(name,[]))
        result.append({'package':name,'locked':versions,'latest_stable':latest,'status':'current' if versions==[latest] else 'Review required — newer stable release or duplicate old version','source':'https://crates.io/crates/'+name})
    return result
if __name__=='__main__':print(json.dumps(check(),indent=2))
