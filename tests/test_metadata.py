from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import importlib.util
from pathlib import Path
import tempfile
import unittest
from tests.fixtures.histories import HistoryBuilder, modules, inventory
from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job, qualify_toolchain

ROOT=Path(__file__).resolve().parents[1]
class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.tools=qualify_toolchain(TEST_GIT,TEST_LFS,Limits())
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.metadata'),'historical metadata is not implemented')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.fixture=HistoryBuilder(Path(self.tmp.name));self.fixture.repository('main')
    def calculate(self,files):
        from historycrate.acquire import RepositoryPool
        from historycrate.closure import build_closure
        f=self.fixture;tip=f.commit('main',files);spec=f.spec([('release','main',(tip,))])
        with Job(spec.limits,self.tools,source_paths=(f.repos['main'],)) as j:return build_closure(spec,RepositoryPool(spec,j),j)
    def test_metadata_includes_unknown_keys_duplicates_custom_update_refused(self):
        for raw in [b'[include]\npath=/does/not/exist\n',b'[submodule "x"]\npath=x\nurl=../x\nupdate=!touch trap\n',b'[submodule "x"]\npath=x\npath=y\nurl=../x\n',b'[submodule "x"]\npath=x\nurl=../x\nunknown=1\n',b'[submodule "x"]\npath=x\nurl=../x\n[submodule "y"]\npath=x\nurl=../x\n',b'[submodule "bad name"]\npath=x\nurl=../x\n']:
            with self.subTest(raw=raw),self.assertRaises(CrateError):self.calculate({'.gitmodules':raw})
    def test_supported_inactive_gitmodules_optional_keys(self):
        raw=modules(('old','gone','../old'))+b' branch=main\n ignore=all\n shallow=true\n fetchRecurseSubmodules=false\n update=checkout\n'
        self.assertEqual(self.calculate({'.gitmodules':raw}).gitlinks,())
    def test_unknown_filter_encoding_ident_and_invalid_text_eol_refused(self):
        for attr in [b'filter=arbitrary',b'working-tree-encoding=UTF-16',b'ident',b'text=unknown',b'eol=unknown',b'filter=lfs text',b'filter=lfs -text eol=lf']:
            with self.subTest(attr=attr),self.assertRaises(CrateError):self.calculate({'.gitattributes':b'file '+attr+b'\n','file':b'contents'})
    def test_metadata_regular_nonlfs_and_attribute_limits(self):
        for name in ('.gitmodules','.gitattributes'):
            with self.subTest(name=name),self.assertRaises(CrateError):self.calculate({'.gitattributes':b'* filter=lfs -text\n',**({name:b''} if name!='.gitattributes' else {})})
    def test_source_info_attributes_and_filter_hooks_are_inert(self):
        f=self.fixture;source=f.repos['main'];(source/'info').mkdir(exist_ok=True);(source/'info/attributes').write_bytes(b'* filter=trap ident\n')
        marker=f.root/'trap-fired';(source/'config').write_text((source/'config').read_text()+f'\n[filter "trap"]\n clean = touch {marker}\n smudge = touch {marker}\n[core]\n fsmonitor = touch {marker}\n')
        before=inventory(source);c=self.calculate({'file':b'plain\n'});self.assertFalse(marker.exists())
        # Fixture commit creation is intentional; comparison surrounds only the source read below.
        from historycrate.acquire import RepositoryPool
        from historycrate.closure import build_closure
        tip=c.commits[0].oid;spec=f.spec([('release','main',(tip,))]);before=inventory(source)
        with Job(spec.limits,self.tools,source_paths=(source,)) as j:build_closure(spec,RepositoryPool(spec,j),j)
        self.assertEqual(before,inventory(source));self.assertFalse(marker.exists())

    def test_metadata_and_conversion_preserve_preexisting_scratch_entries(self):
        from historycrate.acquire import RepositoryPool
        from historycrate.objects import ObjectReader
        from historycrate.metadata import read_gitmodules,verify_conversion,attributes_at
        f=self.fixture;tip=f.commit('main',{'.gitmodules':modules(('old','gone','../old')),'file':b'plain'})
        spec=f.spec([('release','main',(tip,))])
        with Job(spec.limits,self.tools,source_paths=(f.repos['main'],)) as j:
            reader=ObjectReader(RepositoryPool(spec,j).get('main'),j)
            artifact=j.root/'historical-gitmodules';artifact.write_bytes(b'preserve')
            try:read_gitmodules(reader,tip)
            except (CrateError,FileExistsError):pass
            else:self.fail('preexisting metadata artifact was not refused')
            self.assertTrue(artifact.exists(),'preexisting metadata artifact deleted')
            self.assertEqual(artifact.read_bytes(),b'preserve')
            blob=next(x.oid for x in reader.tree(reader.commit(tip).tree) if x.name==b'file')
            artifact=j.root/'artifacts'/'conversion-payload';artifact.write_bytes(b'preserve')
            try:verify_conversion(reader,tip,'file',blob,attributes_at(reader,tip,('file',))['file'],j)
            except (CrateError,FileExistsError):pass
            else:self.fail('preexisting conversion artifact was not refused')
            self.assertTrue(artifact.exists(),'preexisting conversion artifact deleted')
            self.assertEqual(artifact.read_bytes(),b'preserve')
