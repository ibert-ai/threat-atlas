import sys,unittest
from cvss_score import base_score
class Scores(unittest.TestCase):
 def test_known_vectors(self):
  for v,s in [('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',9.8),('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',7.5),('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',5.5),('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',0)]:self.assertEqual(base_score(v),s)
 def test_unknown_is_not_zero(self):
  for v in (None,'broken','CVSS:4.0/unsupported'):self.assertIsNone(base_score(v))
 def test_descending_unknown_last(self):
  values=[None,5.5,9.8,0,7.5];self.assertEqual(sorted(values,key=lambda s:-1 if s is None else s,reverse=True),[9.8,7.5,5.5,0,None])
if __name__=='__main__':unittest.main()
