"""End-to-end original recursive history restore contracts."""
import hashlib,importlib.util,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job,qualify_toolchain
from tests.fixtures.histories import HistoryBuilder,modules,native,inventory
ROOT=Path(__file__).resolve().parents[1]

class RestoreTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.tools=qualify_toolchain(TEST_GIT,TEST_LFS,Limits())
 def setUp(self):
  self.assertIsNotNone(importlib.util.find_spec('historycrate.restore'),'recursive restore is not implemented')
  from historycrate.restore import restore_verified
  from historycrate.packet import build_packet,verify_packet
  self.restore=restore_verified;self.build=build_packet;self.verify=verify_packet
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  f=self.f=HistoryBuilder(self.root)
  for r in ('main','child','leaf'):f.repository(r)
  self.payload=b'original restored LFS payload\x00\n';self.sha=hashlib.sha256(self.payload).hexdigest()
  pointer=f'version https://git-lfs.github.com/spec/v1\noid sha256:{self.sha}\nsize {len(self.payload)}\n'.encode()
  self.leaf=f.commit('leaf',{'leaf':b'nested'})
  files={'.gitmodules':modules(('nested','nested','../leaf')),'.gitattributes':b'*.bin filter=lfs -text\n','nested':(0o160000,self.leaf),'space apostrophe\'.bin':(0o100755,f.blob('child',pointer)),'empty.bin':b'',':wq':b'literal', '-leading':b'dash'}
  self.child=f.commit('child',files)
  cache=f.repos['child']/'lfs/objects'/self.sha[:2]/self.sha[2:4];cache.mkdir(parents=True);(cache/self.sha).write_bytes(self.payload)
  self.first=f.commit('main',{'.gitmodules':modules(('dep','old','../child')),'old':(0o160000,self.child)})
  self.absent=f.commit('main',{'.gitmodules':modules(('dep','old','../child')),'old':b'now regular'},(self.first,))
  self.tip=f.commit('main',{'.gitmodules':modules(('dep','new','../changed'),('shared','shared','../child')),'new':(0o160000,self.child),'shared':(0o160000,self.child),'.gitattributes':b'*.txt text eol=crlf\n','text.txt':b'one\ntwo\n'},(self.absent,))
  self.spec=f.spec([('release','main',(self.tip,))],[('main','old','../child','child'),('main','new','../changed','child'),('main','shared','../child','child'),('child','nested','../leaf','leaf')])
 def job(self):return Job(self.spec.limits,self.tools,source_paths=tuple(r.git_dir for r in self.spec.repositories))
 def test_delete_reintroduce_rename_nested_shared_native_clean(self):
  before=inventory(self.root)
  with self.job() as job:
   staged,_=self.build(self.spec,job);verified=self.verify(staged,job)
   for commit in (self.first,self.absent,self.tip):
    output=self.root/('restored-'+commit[:8]);result=self.restore(verified,'release',commit,output,job)
    self.assertEqual(result.commit,commit);self.assertEqual(native(output,'rev-parse','HEAD').strip().decode(),commit)
    self.assertEqual(native(output,'status','--porcelain=v1','--untracked-files=all'),b'')
    self.assertEqual(native(output,'diff','--no-ext-diff','--no-textconv','--exit-code'),b'')
    self.assertEqual(native(output,'diff','--cached','--no-ext-diff','--no-textconv','--exit-code'),b'')
    subs=native(output,'submodule','status','--recursive');self.assertTrue(all(line[:1]==b' ' for line in subs.splitlines()))
    if commit==self.absent:self.assertEqual((output/'old').read_bytes(),b'now regular');self.assertEqual(subs,b'')
    else:
     paths=('old',) if commit==self.first else ('new','shared')
     for p in paths:
      child=output/p;self.assertTrue((child/'.git').is_dir());self.assertTrue((child/'nested/.git').is_dir())
      self.assertEqual((child/"space apostrophe'.bin").read_bytes(),self.payload)
      self.assertEqual((child/"space apostrophe'.bin").stat().st_mode&0o777,0o755)
      self.assertEqual((child/'empty.bin').read_bytes(),b'')
      self.assertEqual((child/'.git/lfs/objects'/self.sha[:2]/self.sha[2:4]/self.sha).read_bytes(),self.payload)
      self.assertEqual(native(child,'status','--porcelain=v1','--untracked-files=all'),b'')
     if commit==self.tip:self.assertEqual((output/'text.txt').read_bytes(),b'one\r\ntwo\r\n')
  after=inventory(self.root)
  self.assertEqual(before,{k:v for k,v in after.items() if not k.startswith('restored-')})
 def test_only_root_ancestor_and_real_rehearsal(self):
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job)
   with self.assertRaises(CrateError):self.restore(verified,'release',self.child,None,job)
   result=self.restore(verified,'release',self.absent,None,job)
   self.assertIsNone(result.destination);self.assertIn('native-clean-status',result.checks)
 def test_published_config_no_staging_and_global_filter_override(self):
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job);output=self.root/'output';self.restore(verified,'release',self.tip,output,job)
   config=(output/'new/.git/config').read_text();self.assertNotIn(str(job.root),config)
   self.assertIn('/dev/null',config);self.assertIn('filter-process --skip',config)
  global_config=self.root/'ordinary-global';global_config.write_text('[filter "lfs"]\n process = git-lfs filter-process\n required = true\n')
  poison=self.root/'poison';poison.mkdir();marker=self.root/'unexpected'
  (poison/'git-lfs').write_text('#!/bin/sh\ntouch '+str(marker)+'\nexit 99\n');(poison/'git-lfs').chmod(0o755)
  env={'PATH':str(poison)+':/usr/bin:/bin','HOME':str(self.root),'GIT_CONFIG_GLOBAL':str(global_config),'GIT_CONFIG_NOSYSTEM':'1','LC_ALL':'C'}
  result=subprocess.run([str(self.tools.git),'-C',str(output/'new/nested'),'status','--porcelain=v1'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,b'');self.assertFalse(marker.exists())
 def test_native_failure_never_publishes(self):
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job);output=self.root/'output'
   with patch('historycrate.restore.check_restored_tree',side_effect=CrateError('RESTORE_POSTCONDITION_FAILED',4)):
    with self.assertRaises(CrateError):self.restore(verified,'release',self.tip,output,job)
   self.assertFalse(output.exists())

 def test_existing_packet_guard_runs_before_native_restore(self):
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job)
   def blocked():raise CrateError('SOURCE_CHANGED',4)
   job._prepublication_checks=(*getattr(job,'_prepublication_checks',()),blocked)
   count=len(job.native.records)
   with self.assertRaises(CrateError):self.restore(verified,'release',self.tip,None,job)
   self.assertEqual(len(job.native.records),count,'an already failed input guard must stop before native work')

 def test_hydrated_file_recleaned_with_normal_global_filter_and_poisoned_path(self):
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job);output=self.root/'moved name';self.restore(verified,'release',self.tip,output,job)
  global_config=self.root/'global-lfs';global_config.write_text('[filter "lfs"]\n process = git-lfs filter-process\n required = true\n')
  poison=self.root/'poison';poison.mkdir();marker=self.root/'executed'
  for executable in ('git','git-lfs'):
   script=poison/executable;script.write_text('#!/bin/sh\ntouch '+str(marker)+'\nexit 99\n');script.chmod(0o755)
  env={'PATH':str(poison)+':/usr/bin:/bin','HOME':str(self.root),'GIT_CONFIG_GLOBAL':str(global_config),'GIT_CONFIG_NOSYSTEM':'1','LC_ALL':'C'}
  filename="space apostrophe'.bin";pointer=self.f.commits['child'][self.child]['files'][filename][1]
  for cwd in (output/'new',output/'shared',output/'new/nested'):
   args=['hash-object','--path='+filename,'--',filename] if cwd.name!='nested' else ['status','--porcelain=v1','--untracked-files=all','--ignore-submodules=none']
   result=subprocess.run([str(self.tools.git),'-C',str(cwd),*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,(pointer+'\n').encode() if cwd.name!='nested' else b'')
  self.assertFalse(marker.exists())

 def mutate_before_check(self,mutate,expected_check=None,commit=None):
  from historycrate.restore import check_restored_tree
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job);output=self.root/'blocked'
   def changed(root,closure,root_id,oid,phase):
    mutate(root,phase)
    return check_restored_tree(root,closure,root_id,oid,phase)
   with patch('historycrate.restore.check_restored_tree',side_effect=changed):
    with self.assertRaises(CrateError) as error:self.restore(verified,'release',commit or self.tip,output,job)
   self.assertFalse(output.exists())
   if expected_check:self.assertEqual(error.exception.context.get('check'),expected_check)

 def test_no_index_flags_hide_dirty_state(self):
  for flag in ('--assume-unchanged','--skip-worktree'):
   with self.subTest(flag=flag):
    self.mutate_before_check(lambda root,phase:native(root/'new','update-index',flag,'--','-leading'),'index-flags')

 def test_unmerged_index_stage_is_refused(self):
  def conflict(root,phase):
   # Use the existing blob, preserve bytes, but replace stage zero by stage one.
   oid=native(root/'new','rev-parse',self.child+':-leading').strip().decode()
   native(root/'new','update-index','--index-info',data=f'0 {"0"*40}\t-leading\n100644 {oid} 1\t-leading\n'.encode())
  self.mutate_before_check(conflict,'index-flags')

 def test_stat_cache_cannot_hide_dirty_materialized_bytes(self):
  def change(root,phase):
   path=root/'new/-leading';before=path.stat();path.write_bytes(b'evil');os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
  self.mutate_before_check(change,'clean-hash')

 def test_ignored_extra_file_is_refused(self):
  def ignored(root,phase):
   (root/'.git/info').mkdir(exist_ok=True);(root/'.git/info/exclude').write_text('hidden-extra\n');(root/'hidden-extra').write_bytes(b'ignored')
  self.mutate_before_check(ignored,'extra-worktree-path')

 def test_wrong_worktree_executable_mode_is_refused(self):
  self.mutate_before_check(lambda root,phase:(root/"new/space apostrophe'.bin").chmod(0o644),'worktree-mode')

 def test_corrupt_lfs_cache_is_refused(self):
  def corrupt(root,phase):
   cache=root/'new/.git/lfs/objects'/self.sha[:2]/self.sha[2:4]/self.sha;cache.write_bytes(b'x'*len(self.payload))
  self.mutate_before_check(corrupt)

 def test_symbolic_head_at_correct_commit_is_refused(self):
  def symbolic(root,phase):
   native(root,'symbolic-ref','HEAD','refs/historycrate/commits/'+self.tip)
  self.mutate_before_check(symbolic,'detached-head')

 def test_unexpected_persistent_config_is_refused(self):
  self.mutate_before_check(lambda root,phase:native(root,'config','--local','remote.unexpected.url','https://example.invalid/source'),'owned-config')

 def test_final_source_packet_change_blocks_publication(self):
  from historycrate.restore import check_restored_tree
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job);output=self.root/'blocked'
   def changed(*args):
    checks=check_restored_tree(*args)
    path=packet/'repos/main.bundle';data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
    return checks
   with patch('historycrate.restore.check_restored_tree',side_effect=changed):
    with self.assertRaises(CrateError) as error:self.restore(verified,'release',self.tip,output,job)
   self.assertEqual(error.exception.code,'SOURCE_CHANGED');self.assertFalse(output.exists())

 def test_rehearsal_enforces_complete_restore_byte_limit(self):
  from dataclasses import replace
  with self.job() as job:
   packet,_=self.build(self.spec,job);verified=self.verify(packet,job)
   job.limits=replace(job.limits,restore_bytes=1)
   with self.assertRaises(CrateError) as error:self.restore(verified,'release',self.absent,None,job)
   self.assertEqual(error.exception.exit_code,5)

 def test_clean_but_wrong_checkout_conversion_bytes_are_refused(self):
  # Native cleaning accepts LF and CRLF here. The checkout contract promises
  # CRLF, so clean hash/status alone cannot establish exact worktree bytes.
  self.mutate_before_check(lambda root,phase:(root/'text.txt').write_bytes(b'one\ntwo\n'),'converted-worktree-bytes')
