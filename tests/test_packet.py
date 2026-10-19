"""Original packet contract fixtures; native inventory is the independent oracle."""
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from tests.fixtures.histories import HistoryBuilder, modules, inventory, native
from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job, qualify_toolchain

ROOT=Path(__file__).resolve().parents[1]
class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools=qualify_toolchain(TEST_GIT,TEST_LFS,Limits())
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.packet'),'packet boundary is not implemented')
        from historycrate.packet import build_packet,verify_packet,encode_manifest
        self.build=build_packet;self.verify=verify_packet;self.encode=encode_manifest
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.f=HistoryBuilder(self.root);self.f.repository('main');self.f.repository('child')
        self.payload=b'original packet payload\x00\n';self.sha=hashlib.sha256(self.payload).hexdigest()
        pointer=f'version https://git-lfs.github.com/spec/v1\noid sha256:{self.sha}\nsize {len(self.payload)}\n'.encode()
        self.child=self.f.commit('child',{'.gitattributes':b'*.bin filter=lfs -text\n','data.bin':pointer})
        cache=self.f.repos['child']/'lfs/objects'/self.sha[:2]/self.sha[2:4];cache.mkdir(parents=True);(cache/self.sha).write_bytes(self.payload)
        self.base=self.f.commit('main',{'first':b'first'})
        self.tip=self.f.commit('main',{'.gitmodules':modules(('dep','data','../child')),'data':(0o160000,self.child)},(self.base,))
        self.unrelated=self.f.commit('main',{'unrelated':b'excluded'},())
        self.spec=self.f.spec([('release','main',(self.tip,))],[('main','data','../child','child')])
    def job(self):return Job(self.spec.limits,self.tools,source_paths=tuple(r.git_dir for r in self.spec.repositories))
    def rehash(self,packet):
        from historycrate.schema import encode_canonical
        complete=json.loads((packet/'COMPLETE.json').read_bytes())
        complete['manifest_sha256']=hashlib.sha256((packet/'manifest.json').read_bytes()).hexdigest()
        for entry in complete['artifacts']:
            raw=(packet/entry['path']).read_bytes();entry.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        (packet/'COMPLETE.json').write_bytes(encode_canonical(complete))
    def test_complete_bundle_seeds_exact_objects_and_fresh_semantics(self):
        before=inventory(self.root)
        with self.job() as job:
            packet,closure=self.build(self.spec,job)
            verified=self.verify(packet,job)
            self.assertEqual(self.encode(closure),self.encode(verified.closure))
            for repo,seeds in closure.seeds.items():
                header=(packet/'repos'/f'{repo}.bundle').read_bytes().split(b'\n\n',1)[0].splitlines()
                self.assertEqual(header[0],b'# v2 git bundle')
                self.assertEqual(set(header[1:]),{f'{oid} refs/historycrate/commits/{oid}'.encode() for oid in seeds})
                staged=verified.private_root/'imported'/'repos'/repo
                actual=native(staged,'cat-file','--batch-all-objects','--batch-check=%(objectname)').decode().splitlines()
                self.assertEqual(set(actual),{o.oid for o in closure.objects if o.repository==repo})
            self.assertNotIn(self.unrelated,{c.oid for c in verified.closure.commits})
            self.assertEqual(verified.payloads.records[0].private_path.read_bytes(),self.payload)
        self.assertEqual(before,inventory(self.root))
    def test_semantic_manifest_repeatable_and_contains_no_private_paths(self):
        manifests=[]
        for _ in range(2):
            with self.job() as job:
                packet,c=self.build(self.spec,job);raw=(packet/'manifest.json').read_bytes();manifests.append(raw)
                self.assertNotIn(str(self.root).encode(),raw);self.assertNotIn(b'../child',raw)
        self.assertEqual(*manifests)
    def test_omitted_semantic_edge_detected_despite_rehashed_complete(self):
        from historycrate.schema import encode_canonical
        with self.job() as job:
            packet,c=self.build(self.spec,job);value=json.loads((packet/'manifest.json').read_bytes());value['gitlinks']=[];value['counts']['gitlinks']=0
            (packet/'manifest.json').write_bytes(encode_canonical(value));self.rehash(packet)
            with self.assertRaises(CrateError):self.verify(packet,job)
    def test_extra_missing_corrupt_packet_files_fail(self):
        for mutation in ('extra','missing','corrupt','symlink','hardlink','version','prerequisite','unauthorized-ref'):
            with self.subTest(mutation=mutation),self.job() as job:
                packet,c=self.build(self.spec,job);payload=packet/'lfs/objects'/self.sha[:2]/self.sha[2:4]/self.sha
                if mutation=='extra':(packet/'unexpected').write_bytes(b'x')
                elif mutation=='missing':payload.unlink()
                elif mutation=='corrupt':payload.write_bytes(b'bad')
                elif mutation=='symlink':payload.unlink();payload.symlink_to(self.root/'missing')
                elif mutation=='hardlink':
                    import os
                    os.link(payload,packet/'alias')
                elif mutation=='version':
                    from historycrate.schema import encode_canonical
                    value=json.loads((packet/'manifest.json').read_bytes());value['version']=2;(packet/'manifest.json').write_bytes(encode_canonical(value));self.rehash(packet)
                else:
                    p=packet/'repos/main.bundle';raw=p.read_bytes();head,body=raw.split(b'\n\n',1)
                    if mutation=='prerequisite':head+=b'\n-'+self.base.encode()+b' unavailable'
                    else:head=head.replace(b'refs/historycrate/commits/',b'refs/heads/')
                    p.write_bytes(head+b'\n\n'+body);self.rehash(packet)
                with self.assertRaises(CrateError):self.verify(packet,job)
    def test_duplicate_json_and_noncanonical_manifest_fail(self):
        from historycrate.packet import decode_manifest
        with self.job() as job:
            packet,c=self.build(self.spec,job);raw=(packet/'manifest.json').read_bytes()
            for bad in (b'{"version":1,"version":1}',raw+b'\n',b'\xef\xbb\xbf'+raw):
                with self.assertRaises(CrateError):decode_manifest(bad)

    def test_source_mutation_after_build_prevents_publication(self):
        from unittest.mock import patch
        from historycrate.packet import create_packet,verify_packet
        output=self.root/'packet-output'
        def mutate(packet,job):
            result=verify_packet(packet,job)
            config=self.f.repos['main']/'config';config.write_bytes(config.read_bytes()+b'\n# source changed\n')
            return result
        with self.job() as job,patch('historycrate.packet.verify_packet',side_effect=mutate):
            with self.assertRaises(CrateError) as ctx:create_packet(self.spec,output,job)
        self.assertEqual(ctx.exception.code,'SOURCE_CHANGED');self.assertFalse(output.exists())

    def test_original_packet_rechecked_before_later_publication(self):
        import shutil
        with self.job() as builder:
            staged,_=self.build(self.spec,builder);external=self.root/'received';shutil.copytree(staged,external)
        with Job(self.spec.limits,self.tools) as job:
            self.verify(external,job)
            (external/'manifest.json').write_bytes(b'changed after verify')
            with self.assertRaises(CrateError) as caught:
                for check in getattr(job,'_prepublication_checks',()):check()
            self.assertEqual(caught.exception.code,'SOURCE_CHANGED')
