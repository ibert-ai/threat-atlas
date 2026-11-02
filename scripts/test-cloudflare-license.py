import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('license_gate',Path(__file__).with_name('check-cloudflare-license.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class GateTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  (self.root/'docs').mkdir();(self.root/'macos').mkdir()
  self.data={'notice_sha256':'a','legal_sha256':'b','notice':'reviewed'}
  (self.root/'docs/CLOUDFLARE-LICENSE.json').write_text(json.dumps(self.data))
  (self.root/'version.json').write_text(json.dumps({'version':'1.2.3','prerelease':'rc.2','build':12}))
 def run_gate(self,data):
  with patch.object(m,'ROOT',self.root),patch.object(m,'fingerprint',return_value=data),patch('sys.argv',['check','--header']):m.main()
 def test_exact_release_identity(self):
  self.run_gate(self.data);text=(self.root/'macos/RadarLicense.h').read_text();self.assertIn('1.2.3-rc.2+12:a:b',text)
 def test_changed_terms_block(self):
  with self.assertRaises(RuntimeError):self.run_gate(dict(self.data,legal_sha256='changed'))
  self.assertFalse((self.root/'macos/RadarLicense.h').exists())
 def test_unreachable_blocks(self):
  with patch.object(m,'fingerprint',side_effect=OSError('offline')),patch('sys.argv',['check']):
   with self.assertRaises(OSError):m.main()
if __name__=='__main__':unittest.main()
