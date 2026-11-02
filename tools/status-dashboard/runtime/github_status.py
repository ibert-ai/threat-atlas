"""Single cached reader for status-only Git branch; no credentials or writes to Git."""
import json,time,threading,urllib.request,urllib.error
from pathlib import Path
ROOT=Path(__file__).parent
FILE=ROOT/'github-status-cache.json'
LOCK=threading.Lock()
try: cache=json.loads(FILE.read_text())
except Exception: cache={'files':{},'checked':None,'error':'Not fetched yet'}
def read():
    with LOCK: return dict(cache)
def refresh():
    global cache
    state=read();state['error']=None
    for name in ('mac','billy'):
        previous=state['files'].get(name,{})
        url='https://raw.githubusercontent.com/ibert-ai/threat-atlas/refs/heads/codex/release-status/status/'+name+'.json'
        headers={'User-Agent':'ThreatAtlas-local-status/1','Accept':'application/json'}
        if previous.get('etag'):headers['If-None-Match']=previous['etag']
        try:
            with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=20) as response:
                data=json.loads(response.read(262144))
                state['files'][name]={'data':data,'etag':response.headers.get('ETag'),'source':url}
        except urllib.error.HTTPError as e:
            if e.code==304:continue
            state['error']='GitHub status HTTP '+str(e.code)+'; previous data retained'
            state['retry_seconds']=max(600,int(e.headers.get('Retry-After','3600')) if e.headers.get('Retry-After','').isdigit() else 3600)
            if e.code in (400,401,404):state['permanent_error']=True
            break
        except Exception:
            state['error']='GitHub status unavailable; previous data retained';state['retry_seconds']=1200;break
    state['checked']=time.time()
    with LOCK:
        cache=state
        temp=FILE.with_suffix('.tmp');temp.write_text(json.dumps(state));temp.replace(FILE)
def run():
    existing=read();checked=existing.get('checked')
    if checked and time.time()-checked<600:time.sleep(600-(time.time()-checked))
    while True:
        refresh();state=read()
        if state.get('permanent_error'):return
        time.sleep(max(state.get('retry_seconds',0),600-time.time()%600))
def start():threading.Thread(target=run,daemon=True).start()
