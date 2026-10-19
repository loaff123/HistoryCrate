"""Real native conversion under exact historical attributes, no source checkout."""
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import tempfile
import unittest
from pathlib import Path
from historycrate.native import Job, qualify_toolchain
from historycrate.limits import Limits
from historycrate.qualification import _blob, _commit

ROOT=Path(__file__).resolve().parents[1]
class ConversionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools=qualify_toolchain(TEST_GIT,TEST_LFS,Limits())
    def test_historical_checkout_clean_native_bytes(self):
        with Job(Limits(),self.tools) as j:
            a=j.native; a.run('init',{'name':'conversion','bare':True})
            blob=_blob(a,'conversion',b'one\ntwo\n')
            old=_commit(a,'conversion',{'.gitattributes':_blob(a,'conversion',b'* text eol=crlf\n'),':wq':blob})
            _commit(a,'conversion',{'.gitattributes':_blob(a,'conversion',b'* -text\n'),':wq':blob})
            a.run('conversion_checkout',{'repo':'conversion','commit':old,'path':':wq','oid':blob,'name':'converted'})
            self.assertEqual((j.root/'artifacts/converted').read_bytes(),b'one\r\ntwo\r\n')
            clean=a.run('conversion_hash',{'repo':'conversion','commit':old,'path':':wq','name':'converted'})
            self.assertEqual(clean.stdout.strip().decode(),blob)

    def test_stored_crlf_is_not_roundtripping_and_punctuation_stays_data(self):
        with Job(Limits(),self.tools) as j:
            a=j.native; a.run('init',{'name':'conversion','bare':True})
            blob=_blob(a,'conversion',b'one\r\n')
            for i,path in enumerate(["apostrophe'file",'space name','-leading',':wq','semi;$(touch trap)']):
                commit=_commit(a,'conversion',{'.gitattributes':_blob(a,'conversion',b'* text eol=crlf\n'),path:blob})
                name='converted'+str(i)
                a.run('conversion_checkout',{'repo':'conversion','commit':commit,'path':path,'oid':blob,'name':name})
                clean=a.run('conversion_hash',{'repo':'conversion','commit':commit,'path':path,'name':name})
                self.assertNotEqual(clean.stdout.strip().decode(),blob)
                self.assertFalse((j.root/'trap').exists())

    def test_existing_conversion_artifact_is_preserved(self):
        from historycrate.errors import CrateError
        with Job(Limits(),self.tools) as j:
            a=j.native;a.run('init',{'name':'conversion','bare':True})
            blob=_blob(a,'conversion',b'contents');commit=_commit(a,'conversion',{'file':blob})
            artifact=j.root/'artifacts'/'occupied';artifact.write_bytes(b'preserve')
            try:a.run('conversion_checkout',{'repo':'conversion','commit':commit,'path':'file','oid':blob,'name':'occupied'})
            except (CrateError,FileExistsError):pass
            else:self.fail('existing conversion path was not refused')
            self.assertTrue(artifact.exists(),'pre-existing artifact was deleted')
            self.assertEqual(artifact.read_bytes(),b'preserve')

    def test_lfs_clean_input_uses_payload_budget(self):
        from historycrate.errors import CrateError
        limits=Limits().lower({'git_object_bytes':64,'lfs_payload_bytes':1024})
        with Job(limits,self.tools) as j:
            j.native.run('init',{'name':'lfs','bare':True})
            payload=b'payload'*100
            result=j.native.run('lfs_clean',{'repo':'lfs','path':'file'},payload)
            import hashlib
            self.assertIn(hashlib.sha256(payload).hexdigest().encode(),result.stdout)
            with self.assertRaises(CrateError) as ctx:j.native.run('lfs_clean',{'repo':'lfs','path':'file'},b'x'*1025)
            self.assertEqual(ctx.exception.context['resource'],'lfs_payload_bytes')
