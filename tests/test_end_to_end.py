"""Public command-line contract on original local data."""
import io,json,tempfile,unittest
from contextlib import redirect_stdout,redirect_stderr
from pathlib import Path
from unittest.mock import patch
from tests.fixtures.histories import HistoryBuilder,inventory,native
from historycrate.cli import main
from tests.toolchain import GIT, LFS
ROOT=Path(__file__).resolve().parents[1]

class EndToEndTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  self.f=HistoryBuilder(self.root);self.f.repository('source')
  self.base=self.f.commit('source',{'first':b'base'});self.tip=self.f.commit('source',{'second':b'tip'},(self.base,))
  self.spec=self.root/'selection.json';self.spec.write_text(json.dumps({'version':1,'repositories':[{'id':'source','git_dir':str(self.f.repos['source'])}],'roots':[{'id':'release','repository':'source','commits':[self.tip]}],'bindings':[]}))
  self.common=['--git',str(GIT),'--git-lfs',str(LFS),'--trust-local-data']
 def invoke(self,args):
  out=io.StringIO();err=io.StringIO()
  with redirect_stdout(out),redirect_stderr(err):code=main(args)
  return code,json.loads(out.getvalue()),err.getvalue()
 def test_inspect_pack_verify_rehearse_restore_explain(self):
  source_before=inventory(self.f.repos['source']);packet=self.root/'packet';restore=self.root/'restore'
  code,report,_=self.invoke(['inspect','--spec',str(self.spec),*self.common])
  self.assertEqual(code,0,report);self.assertEqual(report['status'],'ready');self.assertEqual(report['publication'],'not-published');self.assertEqual(report['rehearsed'],[])
  code,report,_=self.invoke(['pack','--spec',str(self.spec),'--out',str(packet),*self.common])
  self.assertEqual(code,0,report);self.assertEqual(report['publication'],'published');self.assertTrue((packet/'COMPLETE.json').is_file())
  code,report,_=self.invoke(['verify','--packet',str(packet),*self.common])
  self.assertEqual(code,0,report);self.assertEqual(report['rehearsed'],[]);self.assertNotIn('verified',report)
  code,report,_=self.invoke(['verify','--packet',str(packet),'--rehearse','release',self.base,*self.common])
  self.assertEqual(code,0,report);self.assertEqual(report['rehearsed'],[{'root':'release','commit':self.base}])
  code,report,_=self.invoke(['restore','--packet',str(packet),'--root','release','--commit',self.tip,'--out',str(restore),*self.common])
  self.assertEqual(code,0,report);self.assertEqual(report['publication'],'published');self.assertEqual(native(restore,'status','--porcelain=v1'),b'')
  code,report,_=self.invoke(['explain','--packet',str(packet),'--repo','source','--commit',self.base,*self.common])
  self.assertEqual(code,0,report);self.assertEqual(report['explanation']['reasons'][0]['kind'],'parent')
  self.assertEqual(inventory(self.f.repos['source']),source_before)
  for field in ('limits','observations','counts','structural_checks','trust_acknowledged','profile','report_version'):self.assertIn(field,report)
  self.assertTrue(report['trust_acknowledged'])
  self.assertEqual(report['counts']['commits'],2)
  self.assertIn('sampled',report['observations']['kind'])
  self.assertIn('sampled',report['limits']['observed_rss_bytes']['kind'])
  self.assertIn('preflight',report['preflight']['kind'])
  self.assertEqual(report['rehearsed'],[])
 def test_trust_and_tool_paths_required(self):
  for args in (['inspect','--spec',str(self.spec)],['inspect','--spec',str(self.spec),*self.common[:-1]]):
   code,report,_=self.invoke(args);self.assertEqual(code,2);self.assertEqual(report['status'],'blocked')
 def test_pack_revalidates_source_and_never_publishes_on_failure(self):
  code,report,_=self.invoke(['inspect','--spec',str(self.spec),*self.common]);self.assertEqual(code,0,report)
  (self.f.repos['source']/'shallow').touch();output=self.root/'output'
  code,report,_=self.invoke(['pack','--spec',str(self.spec),'--out',str(output),*self.common])
  self.assertEqual(code,3,report);self.assertEqual(report['publication'],'not-published');self.assertFalse(output.exists())
 def test_postpublication_failure_status_survives_cli(self):
  from historycrate.errors import CrateError
  with patch('historycrate.cli.doctor'),patch('historycrate.cli.create_packet',side_effect=CrateError('PUBLISHED_DURABILITY_UNCERTAIN',6,{'publication':'published-durability-uncertain'}),create=True):
   code,report,_=self.invoke(['pack','--spec',str(self.spec),'--out',str(self.root/'output'),*self.common])
  self.assertEqual(code,6);self.assertEqual(report['publication'],'published-durability-uncertain')
