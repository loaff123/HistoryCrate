from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS, GIT_EXEC as TEST_GIT_EXEC
import importlib.util
import io
import json
import os
from pathlib import Path
import resource
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
GIT=TEST_GIT
LFS=TEST_LFS

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.native'), 'controlled native adapter is not implemented')
        from historycrate import native
        from historycrate.limits import Limits
        self.n=native
        self.limits=Limits()
        self.tools=native.qualify_toolchain(GIT,LFS,self.limits)
        self.job=native.Job(self.limits,self.tools)
        self.job.__enter__()
        self.addCleanup(self.job.__exit__,None,None,None)
        self.a=self.job.native

    def test_exact_toolchain_and_inherited_limits(self):
        self.assertEqual(self.tools.git_version,'2.52.0')
        self.assertEqual(self.tools.lfs_version,'3.8.0')
        self.assertEqual(self.tools.git_exec_path,TEST_GIT_EXEC)
        before=resource.getrlimit(resource.RLIMIT_AS)
        self.a.run('lfs_version',{})
        self.assertEqual(resource.getrlimit(resource.RLIMIT_AS),before)

    def test_old_lfs_wrong_name_and_source_tool_refused(self):
        from historycrate.errors import CrateError
        # Exercise version admission deterministically, without assuming a host
        # happens to have an older second LFS installation.
        from dataclasses import replace
        execute=self.n.run_process
        def old_version(*args,**kwargs):
            result=execute(*args,**kwargs)
            if tuple(args[0])==(str(LFS),'version'):
                result=replace(result,stdout=b'git-lfs/3.6.1 (GitHub; linux amd64; go go1.23; git deadbeef)\n')
            return result
        with patch('historycrate.native.run_process',side_effect=old_version):
            with self.assertRaises(CrateError) as caught:self.n.qualify_toolchain(GIT,LFS,self.limits)
        self.assertEqual(caught.exception.code,'UNQUALIFIED_LFS_VERSION')
        with self.assertRaises(CrateError):self.n.qualify_toolchain(Path('/bin/echo'),LFS,self.limits)
        with self.assertRaises(CrateError):self.n.Job(self.limits,self.tools,source_paths=(LFS.parent,)).__enter__()

    def test_fresh_environment_configuration_and_registry(self):
        from historycrate.errors import CrateError
        poison={'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'alias.version','GIT_CONFIG_VALUE_0':'!false','GIT_CONFIG_GLOBAL':'/does/not/exist','GIT_DIR':'/does/not/exist','SSH_AUTH_SOCK':'secret','HTTPS_PROXY':'secret','PATH':'/does/not/exist'}
        with patch.dict(os.environ,poison):
            with self.n.Job(self.limits,self.tools) as j:
                self.assertEqual(j.native.run('git_version',{}).stdout,b'git version 2.52.0\n')
                self.assertNotIn('SSH_AUTH_SOCK',j.native.environment)
                self.assertNotIn('HTTPS_PROXY',j.native.environment)
                self.assertEqual(j.native.environment['GIT_ALLOW_PROTOCOL'],'')
                j.native.run('init',{'name':'clean','bare':False})
                cfg=j.native.run('config_list',{'repo':'clean'}).stdout
                self.assertIn(b'filter.lfs.process\nPATH=',cfg)
                self.assertIn(b' filter-process --skip\0',cfg)
                self.assertIn(b'protocol.allow\nnever\0',cfg)
                with self.assertRaises(CrateError):j.native.run('fetch',{'url':'https://example.invalid'})
                with self.assertRaises(CrateError):j.native.run('git_version',{'args':['status']})

    def test_native_object_bundle_and_framed_stream(self):
        self.a.run('init',{'name':'one','bare':True})
        blob=self.a.run('hash_blob',{'repo':'one','write':True},b'hello\n').stdout.strip().decode()
        tree=self.a.run('make_tree',{'repo':'one'},f'100644 blob {blob}\tfile\0'.encode()).stdout.strip().decode()
        commit=self.a.run('commit_tree',{'repo':'one','tree':tree,'parents':()},b'fixture\n').stdout.strip().decode()
        self.a.run('update_ref',{'repo':'one','oid':commit})
        self.a.run('fsck',{'repo':'one'})
        self.a.run('bundle_create',{'repo':'one','name':'tiny'})
        self.a.run('bundle_verify',{'repo':'one','name':'tiny'})
        sink=io.BytesIO()
        result=self.a.stream('cat_object',{'repo':'one','oid':blob},io.BytesIO(),sink)
        self.assertEqual(sink.getvalue(),b'hello\n')
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'')

    def test_lfs_clean_skip_smudge_and_empty_file(self):
        self.a.run('init',{'name':'lfs','bare':False})
        import hashlib
        payload=b'original fixture payload\n'
        expected=f'version https://git-lfs.github.com/spec/v1\noid sha256:{hashlib.sha256(payload).hexdigest()}\nsize {len(payload)}\n'.encode()
        for name in [':wq',"apostrophe'file",'-leading','space name','semi;dollar$(x)']:
            result=self.a.run('lfs_clean',{'repo':'lfs','path':name},payload)
            self.assertEqual(result.stdout,expected)
            self.assertEqual(self.a.run('lfs_smudge',{'repo':'lfs','path':name},expected).stdout,expected)
        self.assertEqual(self.a.run('lfs_clean',{'repo':'lfs','path':'empty'},b'').stdout,b'')

    def test_inert_source_config_and_original_bytes_unchanged(self):
        self.a.run('init',{'name':'source','bare':True})
        path=self.job.root/'inert-source-config'
        content=b'[core]\nrepositoryformatversion = 0\n[filter "trap"]\nclean = touch /never-run\n[credential]\nhelper = !touch /never-run\n'
        path.write_bytes(content)
        parsed=self.a.run('parse_config',{'name':'inert-source-config'})
        self.assertIn(b'filter.trap.clean\ntouch /never-run\0',parsed.stdout)
        self.assertEqual(path.read_bytes(),content)

    def test_doctor_qualifies_real_native_capabilities(self):
        report=self.n.doctor(GIT,LFS,self.limits)
        self.assertEqual(report['status'],'passed')
        self.assertEqual(report['profile'],'trusted-local-v1')
        for check in ['bundle','historical_attributes','text_roundtrip','lfs_empty','lfs_exact_pointer','lfs_internal_git','fixed_filter_punctuation','normal_global_lfs_process_pinned','source_config_inert','source_objects_copied','atomic_noreplace','helper_trap_positive_controls','helper_traps_suppressed','transport_denied']:
            self.assertIn(check,report['checks'])
        self.assertEqual(report['ordinary_trace']['internal_git_versions'],['2.52.0'])
        self.assertGreater(report['ordinary_trace']['internal_git_version_events'],0)
        self.assertFalse(report['os_sandbox'])
        self.assertEqual(report['publication'],'not-published')
        self.assertEqual(report['rehearsed'],[])
        self.assertIn('observed',report['resource_observation'])

    def test_framed_small_cap_admits_exact_payload_and_refuses_next_byte(self):
        from historycrate.errors import CrateError
        self.a.run('init',{'name':'small','bare':True})
        one=self.a.run('hash_blob',{'repo':'small','write':True},b'abc').stdout.strip().decode()
        two=self.a.run('hash_blob',{'repo':'small','write':True},b'abcd').stdout.strip().decode()
        self.a.limits=self.limits.lower({'git_object_bytes':3})
        sink=io.BytesIO();self.a.stream('cat_object',{'repo':'small','oid':one},io.BytesIO(),sink)
        self.assertEqual(sink.getvalue(),b'abc')
        with self.assertRaises(CrateError):self.a.stream('cat_object',{'repo':'small','oid':two},io.BytesIO(),io.BytesIO())

    def test_wrong_exec_path_identity_is_refused(self):
        from dataclasses import replace
        from historycrate.errors import CrateError
        import shutil
        alternate=self.job.root/'unqualified-exec-path';alternate.mkdir()
        shutil.copyfile(GIT,alternate/'git');(alternate/'git').chmod(0o700)
        wrong=replace(self.tools,git_exec_path=alternate)
        with self.n.Job(self.limits,wrong) as job:
            with self.assertRaises(CrateError):job.native.run('git_version',{})

    def test_trace_rejects_synthetic_conflicting_internal_git_version(self):
        from historycrate.qualification import _blob,_commit,_trace_lfs
        from historycrate.errors import CrateError
        self.a.run('init',{'name':'conflict','bare':False})
        repo=self.a._repo('conflict');payload=b'conflicting-path fixture'
        pointer=self.a.run('lfs_clean',{'repo':'conflict','path':'data.bin'},payload).stdout
        pointer_oid=_blob(self.a,'conflict',pointer)
        commit=_commit(self.a,'conflict',{
            '.gitattributes':_blob(self.a,'conflict',b'*.bin filter=lfs -text\n'),
            'data.bin':pointer_oid})
        self.a.run('read_tree',{'repo':'conflict','commit':commit})
        self.a.run('checkout_index',{'repo':'conflict'})
        (repo/'data.bin').write_bytes(payload)
        # Real Git/LFS operation and trace, with a deliberately synthetic wrong
        # internal version event. This is a validator negative, not evidence that
        # another Git installation was present or executed on this host.
        execute=self.a._execute
        def conflicting_trace(*args,**kwargs):
            result=execute(*args,**kwargs)
            trace=Path(kwargs['env']['GIT_TRACE2_EVENT'])
            events=[json.loads(line) for line in trace.read_text().splitlines()]
            internal=[e for e in events if e.get('event')=='version' and '/' in e.get('sid','')]
            self.assertTrue(internal)
            internal[0]['exe']='0.0.0-synthetic-conflict'
            trace.write_text(''.join(json.dumps(e)+'\n' for e in events))
            return result
        with patch.object(self.a,'_execute',side_effect=conflicting_trace),self.assertRaises(CrateError) as error:
            _trace_lfs(self.a,repo,'data.bin',pointer_oid)
        self.assertEqual(error.exception.code,'LFS_INTERNAL_GIT_MISMATCH')

if __name__=='__main__':unittest.main()
