"""Offline provenance checks. No third-party history is downloaded or executed."""
import hashlib,json,unittest
from pathlib import Path

class ExternalProvenanceTests(unittest.TestCase):
 def test_pinned_cholla_metadata_and_exact_notice(self):
  value=json.loads((Path(__file__).parent/'external/cholla.json').read_text())
  notice=value['license']['original_notice_utf8'].encode()
  self.assertEqual(len(notice),1080)
  self.assertEqual(hashlib.sha256(notice).hexdigest(),'0d24d0d26d43227625c30aeedbf67b0df53a3bb00ed3893aec219b40a6f5c90a')
  self.assertEqual(value['selection']['selected_root_commits'],['d18e7bb8e167cea183e7da56f2043b85cab50068'])
  self.assertEqual([x['root_commit'] for x in value['rehearsals']],['988e4c5bb8e343d3e3bc4f10cf354595e4b660e9','96e92f3413a5afeea240593d99e6869d597a78f9','d18e7bb8e167cea183e7da56f2043b85cab50068'])
  payloads=value['required_payloads']
  self.assertEqual(len(payloads),11);self.assertEqual(sum(x['size'] for x in payloads.values()),28989160)
  canonical=json.dumps(payloads,sort_keys=True,separators=(',',':')).encode()
  self.assertEqual(hashlib.sha256(canonical).hexdigest(),'9f07c00e9235be55dac1391f407c45dabcbfa3b63c571f076d46ea2d6cae774e')
  self.assertEqual(value['expected_closure']['root_commits'],2518)
  self.assertEqual(value['expected_closure']['dependency_commits'],12)
  self.assertEqual(len(value['selection']['historical_dependency_seeds']),6)
  raw=json.dumps(value)
  for private in ('/workspace/','/home'+'/agent/','/tmp'+'/historycrate-public-'):self.assertNotIn(private,raw)
