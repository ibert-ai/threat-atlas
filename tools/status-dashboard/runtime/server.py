import json, socket, sqlite3, time, ipaddress, os
import releases
import github_status
import google_auth_atlas
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
ROOT=Path(__file__).parent
DB=sqlite3.connect(ROOT/'monitor.sqlite3')
DB.execute('CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY, sender TEXT, target TEXT, body TEXT, status TEXT, created REAL)')
DB.execute('CREATE TABLE IF NOT EXISTS agents(host TEXT PRIMARY KEY, status TEXT, detail TEXT, seen REAL)')
DB.execute('CREATE TABLE IF NOT EXISTS services(host TEXT, name TEXT, status TEXT, detail TEXT, seen REAL, PRIMARY KEY(host,name))')
DB.execute('CREATE TABLE IF NOT EXISTS mac_tasks(id INTEGER PRIMARY KEY,request_id TEXT UNIQUE,project TEXT,title TEXT,body TEXT,status TEXT,created REAL)')
DB.commit()
def health(status,seen,now=None):
 now=time.time() if now is None else now
 if seen is None or now-seen>90: return 'red'
 if status=='unresponsive': return 'red'
 if now-seen>45 or status!='ok': return 'yellow'
 return 'green'
ALLOWED_NETWORK=ipaddress.ip_network('10.0.88.0/24')
ALLOWED_HOSTS={'roberts-air:8765','127.0.0.1:8765','localhost:8765','10.0.88.189:8765','roberts-macbook-air.local:8765'}
PORT=int(os.environ.get('MONITOR_PORT','8765'))
if PORT!=8765: ALLOWED_HOSTS={'127.0.0.1:'+str(PORT),'localhost:'+str(PORT)}
class Handler(BaseHTTPRequestHandler):
 def allowed(self):
  peer=ipaddress.ip_address(self.client_address[0])
  if not (peer.is_loopback or peer in ALLOWED_NETWORK):
   self.reply({'error':'Access restricted to 10.0.88.0/24 and loopback'},403);return False
  if self.headers.get('Host','').lower() not in ALLOWED_HOSTS:
   self.reply({'error':'Unrecognized dashboard hostname'},403);return False
  return True
 def reply(self,data,status=200):
  payload=json.dumps(data).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(payload)
 def do_GET(self):
  if not self.allowed(): return
  if self.path=='/login':
   google_auth_atlas.reply_page(self);return
  if not google_auth_atlas.authenticated(self):
   if self.path.startswith('/api/'):
    self.reply({'error':'Sign in at /login'},401);return
   self.send_response(302);self.send_header('Location','/login');self.end_headers();return
  if self.path in ('/agents','/agents/'):
   self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write((ROOT/'agents.html').read_bytes()); return
  if self.path=='/api/tasks':
   self.reply({'tasks':[dict(zip(['id','project','title','status','created'],row)) for row in DB.execute('SELECT id,project,title,status,created FROM mac_tasks ORDER BY id DESC LIMIT 100')]});return
  if self.path=='/':
   self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write((ROOT/'index.html').read_bytes()); return
  if self.path=='/api/state':
   agents=[dict(zip(['host','status','detail','seen'],r)) for r in DB.execute('SELECT * FROM agents')]
   for host in [socket.gethostname(),'BILLY-BADASS']:
    if not any(a['host']==host for a in agents): agents.append(dict(host=host,status='Unverified',detail='No agent report received',seen=None))
   for a in agents:
    a['color']=health(a['status'],a['seen']); a['services']=[dict(zip(['name','status','detail','seen'],r)) for r in DB.execute('SELECT name,status,detail,seen FROM services WHERE host=?',(a['host'],))]
    for service in a['services']: service['color']=health(service['status'],service['seen'])
    colors=[a['color']]+[v['color'] for v in a['services']]
    a['color']=max(colors,key={'green':0,'yellow':1,'red':2}.get)
   self.reply(dict(server=socket.gethostname(),agents=agents,commands=[dict(zip(['id','sender','target','body','status','created'],r)) for r in DB.execute('SELECT * FROM commands ORDER BY id DESC')])); return
  if self.path=='/api/project-status':
   self.reply(github_status.read()); return
  if self.path=='/api/releases':
   self.reply(releases.read_cache()); return
  self.reply({'error':'Not found'},404)
 def do_POST(self):
  if not self.allowed(): return
  if self.path=='/auth/logout':
   google_auth_atlas.logout(self);return
  if self.path=='/auth/google':
   google_auth_atlas.login(self);return
  if not google_auth_atlas.authenticated(self):
   self.reply({'error':'Google sign-in required'},401);return
  if self.path!='/api/report' and not (ipaddress.ip_address(self.client_address[0]).is_loopback or (self.path=='/api/tasks' and self.client_address[0]=='10.0.88.189')): self.reply({'error':'Command changes are restricted to the Mac'},403); return
  if self.headers.get('Origin') not in ({None}|{'http://'+h for h in ALLOWED_HOSTS}): self.reply({'error':'Origin rejected'},403); return
  try:
   size=int(self.headers.get('Content-Length','0'))
   if not 0<size<=16384: raise ValueError('Invalid request size')
   data=json.loads(self.rfile.read(size))
   if self.path=='/api/tasks':
    request_id=data.get('request_id','');project=data.get('project','');title=data.get('title','');body=data.get('body','')
    if not all(isinstance(v,str) for v in (request_id,project,title,body)) or not 1<=len(request_id)<=100 or not 1<=len(title)<=200 or not 1<=len(body)<=8000 or project not in ('Threat Atlas','Will you survive','Other'):raise ValueError('Invalid task fields')
    title=title.strip();body=body.strip()
    if not title or not body:raise ValueError('Task title and instructions required')
    DB.execute('INSERT OR IGNORE INTO mac_tasks(request_id,project,title,body,status,created) VALUES(?,?,?,?,?,?)',(request_id,project,title,body,'Queued for MAC manual review',time.time()));DB.commit()
    row=DB.execute('SELECT id FROM mac_tasks WHERE request_id=?',(request_id,)).fetchone();self.reply({'ok':True,'id':row[0],'status':'Queued for MAC manual review'});return
   elif self.path=='/api/commands':
    target=data['target']; body=data['body'].strip()
    if not body or len(body)>8000 or len(target)>200: raise ValueError('Invalid command')
    DB.execute('INSERT INTO commands(sender,target,body,status,created) VALUES(?,?,?,?,?)',(socket.gethostname(),target,body,'Queued locally',time.time()))
   elif self.path=='/api/report':
    host=data['host']; status=data['status']; detail=data.get('detail','')
    if not all(isinstance(v,str) and len(v)<=8000 for v in [host,status,detail]): raise ValueError('Invalid report')
    if status not in ('ok','warning','waiting_permission','unresponsive'): raise ValueError('Invalid status')
    services=data.get('services',[])
    if not isinstance(services,list) or len(services)>30: raise ValueError('Invalid services')
    for service in services:
     if not isinstance(service,dict) or service.get('status') not in ('ok','warning','waiting_permission','unresponsive'): raise ValueError('Invalid service')
     if not isinstance(service.get('name'),str) or not isinstance(service.get('detail',''),str): raise ValueError('Invalid service fields')
    now=time.time()
    DB.execute('INSERT OR REPLACE INTO agents VALUES(?,?,?,?)',(host,status,detail,now))
    DB.execute('DELETE FROM services WHERE host=?',(host,))
    for service in services: DB.execute('INSERT OR REPLACE INTO services VALUES(?,?,?,?,?)',(host,service['name'],service['status'],service.get('detail',''),now))
   elif self.path=='/api/complete':
    DB.execute('UPDATE commands SET status=? WHERE id=?',('Marked complete manually',int(data['id'])))
   else: self.reply({'error':'Not found'},404); return
   DB.commit(); self.reply({'ok':True})
  except (ValueError,KeyError,TypeError) as exc: self.reply({'error':str(exc)},400)
print('Agent monitor port '+str(PORT)+('; LAN 10.0.88.0/24 and loopback' if PORT==8765 else '; loopback preview only'),flush=True)
releases.start()
github_status.start()
HTTPServer(('0.0.0.0' if PORT==8765 else '127.0.0.1',PORT),Handler).serve_forever()
