import importlib.util,json,os,shutil,subprocess,tempfile,time,unittest,urllib.request,urllib.error
from pathlib import Path
RUNTIME=Path(__file__).parent/'runtime'
class DashboardTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)
  for name in ('server.py','google_auth_atlas.py','index.html','agents.html'):shutil.copy2(RUNTIME/name,cls.root/name)
  for name in ('releases.py','github_status.py'):(cls.root/name).write_text('def start():pass\ndef read_cache():return {}\ndef read():return {}\n')
  cls.process=subprocess.Popen(['/usr/bin/python3',str(cls.root/'server.py')],env=dict(os.environ,MONITOR_PORT='8767'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for _ in range(50):
   try:urllib.request.urlopen('http://localhost:8767/',timeout=1);break
   except Exception:time.sleep(.1)
 @classmethod
 def tearDownClass(cls):cls.process.terminate();cls.process.wait(timeout=5);cls.tmp.cleanup()
 def post(self,path,data,origin='http://localhost:8767'):
  return urllib.request.urlopen(urllib.request.Request('http://localhost:8767'+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json','Origin':origin}))
 def test_pages_and_sort(self):
  s=urllib.request.urlopen('http://localhost:8767/').read().decode();a=urllib.request.urlopen('http://localhost:8767/agents').read().decode()
  self.assertIn('agent-summary',s);self.assertIn('Known Vulnerabilities',s);self.assertIn('Agent status',a)
 def test_task_queue_is_idempotent(self):
  task={'request_id':'test-dedup-1','project':'Threat Atlas','title':'Test only','body':'Do not execute — isolated acceptance test'}
  x=json.load(self.post('/api/tasks',task));y=json.load(self.post('/api/tasks',task));self.assertEqual(x['id'],y['id']);self.assertEqual(len(json.load(urllib.request.urlopen('http://localhost:8767/api/tasks'))['tasks']),1)
 def test_bad_origin(self):
  with self.assertRaises(urllib.error.HTTPError) as e:self.post('/api/tasks',{},'https://attacker.invalid')
  self.assertEqual(e.exception.code,403)
 def test_invalid_task_types(self):
  with self.assertRaises(urllib.error.HTTPError) as e:self.post('/api/tasks',{'request_id':'bad','project':'Other','title':42,'body':'test'})
  self.assertEqual(e.exception.code,400)
 def test_google_not_configured(self):
  with self.assertRaises(urllib.error.HTTPError) as e:self.post('/auth/google',{})
  self.assertEqual(e.exception.code,503)
 def test_owner_and_nonce(self):
  spec=importlib.util.spec_from_file_location('auth',self.root/'google_auth_atlas.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  claims={'email':'ibert@ibert.se','email_verified':True,'hd':'ibert.se','sub':'test-sub','nonce':'one'};c={'owner_email':'ibert@ibert.se'}
  self.assertEqual(m.verify_claims(claims,'one',c),'test-sub')
  for bad in [dict(claims,email='robert@ibert.se'),dict(claims,nonce='other'),dict(claims,email_verified=False),dict(claims,hd=None)]:
   with self.assertRaises(ValueError):m.verify_claims(bad,'one',c)
if __name__=='__main__':unittest.main()
