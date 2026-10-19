from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import hashlib
import importlib.util
from pathlib import Path
import random
import tempfile
import unittest
from tests.fixtures.histories import HistoryBuilder, modules, inventory, native
from tests.oracle import graph
from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job, qualify_toolchain

ROOT=Path(__file__).resolve().parents[1]
class ClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools=qualify_toolchain(TEST_GIT,TEST_LFS,Limits())
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.closure'),'historical closure is not implemented')
        from historycrate.closure import build_closure
        from historycrate.acquire import RepositoryPool
        self.build=build_closure;self.Pool=RepositoryPool
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.fixture=HistoryBuilder(Path(self.temp.name))
    def calculate(self,spec):
        with Job(spec.limits,self.tools,source_paths=tuple(r.git_dir for r in spec.repositories)) as j:
            result=self.build(spec,self.Pool(spec,j),j)
            return result
    def test_full_merge_ancestry_deleted_reintroduced_orphan_gitlinks(self):
        f=self.fixture
        for r in ('main','child'):f.repository(r)
        child_base=f.commit('child',{'data':b'base\n'})
        orphan=f.commit('child',{'data':b'orphan\n'},(child_base,),update=False)
        unrelated_child=f.commit('child',{'other':b'unrelated'},(child_base,))
        old=f.commit('main',{'.gitmodules':modules(('dep','data','../data.git')),'data':(0o160000,orphan)})
        deleted=f.commit('main',{'.gitmodules':modules(('dep','data','../data.git')),'data':b'former module is file'},(old,))
        left=f.commit('main',{'left':b'left'},(deleted,))
        right=f.commit('main',{'right':b'right'},(old,))
        tip=f.commit('main',{'.gitmodules':modules(('dep','data','../data.git')),'data':(0o160000,orphan)},(left,right))
        unrelated=f.commit('main',{'unrelated':b'no inclusion'},())
        spec=f.spec([('release','main',(tip,))],[('main','data','../data.git','child')])
        before=inventory(f.root);c=self.calculate(spec);self.assertEqual(before,inventory(f.root))
        expected={'main':graph.ancestry(f.repos['main'],(tip,)),'child':graph.ancestry(f.repos['child'],(orphan,))}
        self.assertEqual({(x.repository,x.oid) for x in c.commits},{(r,o) for r,oids in expected.items() for o in oids})
        self.assertNotIn(unrelated,c.root_ancestors['release']);self.assertNotIn(unrelated_child,c.seeds['child'])
        self.assertEqual(set(c.root_ancestors['release']),expected['main'])
        self.assertEqual({(x.repository,x.oid) for x in c.objects},{(r,o) for r,seed in [('main',tip),('child',orphan)] for o in graph.objects(f.repos[r],(seed,))})
        self.assertEqual({(x.parent_commit,x.path,x.child_commit) for x in c.gitlinks},graph.gitlinks(f.repos['main'],expected['main']))
    def test_rename_changed_url_exact_binding_and_digest_error(self):
        f=self.fixture;f.repository('main');f.repository('child')
        child=f.commit('child',{'x':b'x'})
        old=f.commit('main',{'.gitmodules':modules(('dep','old','https://secret:token@example.invalid/old')),'old':(0o160000,child)})
        tip=f.commit('main',{'.gitmodules':modules(('dep','new','../new')),'new':(0o160000,child)},(old,))
        bindings=[('main','new','../new','child')]
        with self.assertRaises(CrateError) as ctx:self.calculate(f.spec([('release','main',(tip,))],bindings))
        self.assertEqual(ctx.exception.code,'MISSING_BINDING');self.assertEqual(ctx.exception.context['commit'],old)
        self.assertEqual(ctx.exception.context['path'],'old');self.assertNotIn('secret',str(ctx.exception));self.assertNotIn('token',str(ctx.exception))
        bindings.append(('main','old','https://secret:token@example.invalid/old','child'))
        self.assertEqual(len(self.calculate(f.spec([('release','main',(tip,))],bindings)).gitlinks),2)
    def test_nested_shared_repositories_and_depth_refusal(self):
        f=self.fixture
        for r in ('main','child','leaf'):f.repository(r)
        leaf=f.commit('leaf',{'x':b'x'})
        child=f.commit('child',{'.gitmodules':modules(('leaf','nested','../leaf')),'nested':(0o160000,leaf)})
        tip=f.commit('main',{'.gitmodules':modules(('one','one','../child'),('two','two','../child')),'one':(0o160000,child),'two':(0o160000,child)})
        bindings=[('main','one','../child','child'),('main','two','../child','child'),('child','nested','../leaf','leaf')]
        c=self.calculate(f.spec([('release','main',(tip,))],bindings));self.assertEqual(len(c.commits),3);self.assertEqual(len(c.gitlinks),3)
        with self.assertRaises(CrateError) as ctx:self.calculate(f.spec([('release','main',(tip,))],bindings,Limits().lower({'repository_depth':1})))
        self.assertEqual(ctx.exception.code,'BUDGET_EXCEEDED')
    def test_inactive_metadata_is_not_dependency_and_unused_repository_not_acquired(self):
        f=self.fixture;f.repository('main');f.repository('unused')
        tip=f.commit('main',{'.gitmodules':modules(('unused','gone','../gone')),'gone':b'file'})
        (f.repos['unused']/'shallow').touch()
        c=self.calculate(f.spec([('release','main',(tip,))]));self.assertEqual(len(c.commits),1);self.assertEqual(c.gitlinks,())
    def test_historical_symlink_lfsconfig_and_collision_refused(self):
        for bad in ('symlink','lfsconfig','collision'):
            with self.subTest(bad=bad):
                f=HistoryBuilder(self.fixture.root/bad);f.root.mkdir();f.repository('main')
                files={'link':(0o120000,f.blob('main',b'target'))} if bad=='symlink' else ({'dir/.lfsconfig':b'[lfs]\nurl=x\n'} if bad=='lfsconfig' else {'A':b'a','a':b'b'})
                old=f.commit('main',files);tip=f.commit('main',{'ok':b'ok'},(old,))
                with self.assertRaises(CrateError):self.calculate(f.spec([('release','main',(tip,))]))
    def test_safe_punctuation_and_text_conversion(self):
        f=self.fixture;f.repository('main')
        files={name:b'a\nb\n' for name in [':wq',"apostrophe'file",'space name','-leading']}
        files['.gitattributes']=b'* text eol=crlf\n';tip=f.commit('main',files)
        self.assertEqual(len(self.calculate(f.spec([('release','main',(tip,))])).commits),1)
        bad=f.commit('main',{'.gitattributes':b'* text\n','bad':b'a\r\n'})
        with self.assertRaises(CrateError) as ctx:self.calculate(f.spec([('release','main',(bad,))]))
        self.assertEqual(ctx.exception.code,'CLEAN_ROUNDTRIP_FAILED')
    def test_effective_lfs_occurrences_and_literal_pointer(self):
        f=self.fixture;f.repository('main')
        payload=b'payload';sha=hashlib.sha256(payload).hexdigest();pointer=f'version https://git-lfs.github.com/spec/v1\noid sha256:{sha}\nsize {len(payload)}\n'.encode()
        tip=f.commit('main',{'.gitattributes':b'*.bin filter=lfs -text\n','one.bin':pointer,'empty.bin':b'','literal':pointer})
        c=self.calculate(f.spec([('release','main',(tip,))]));self.assertEqual([(x.path,x.sha256,x.size) for x in c.lfs],[('one.bin',sha,len(payload))])
    def test_budget_counters_and_rebased_child_ancestry(self):
        f=self.fixture;f.repository('main');f.repository('child')
        base=f.commit('child',{'x':b'base'});old=f.commit('child',{'x':b'old'},(base,),update=False)
        rebased=f.commit('child',{'x':b'rebased'},())
        first=f.commit('main',{'.gitmodules':modules(('dep','dep','../child')),'dep':(0o160000,old)})
        tip=f.commit('main',{'.gitmodules':modules(('dep','dep','../child')),'dep':(0o160000,rebased)},(first,))
        spec=f.spec([('release','main',(tip,))],[('main','dep','../child','child')]);c=self.calculate(spec)
        self.assertEqual({x.oid for x in c.commits if x.repository=='child'},{base,old,rebased})
        for resource in ('commits','git_objects','gitlink_occurrences','commit_path_visits','bundle_seed_refs'):
            with self.subTest(resource=resource):
                spec=f.spec([('release','main',(tip,))],[('main','dep','../child','child')],Limits().lower({resource:0}))
                with self.assertRaises(CrateError) as ctx:self.calculate(spec)
                self.assertEqual(ctx.exception.exit_code,5)
    def test_randomized_original_dags_match_native_ancestry_objects(self):
        f=self.fixture;f.repository('main');rng=random.Random(171);commits=[]
        for i in range(9):
            parents=tuple(rng.sample(commits,min(len(commits),rng.randrange(3))))
            commits.append(f.commit('main',{'file':f'commit-{i}\n'.encode()},parents))
        seeds=(commits[-1],commits[-2]);c=self.calculate(f.spec([('release','main',seeds)]))
        self.assertEqual({x.oid for x in c.commits},graph.ancestry(f.repos['main'],seeds))
        self.assertEqual({x.oid for x in c.objects},graph.objects(f.repos['main'],seeds))

    def test_identical_oids_in_distinct_stores_keep_repository_identity(self):
        f=self.fixture
        for repo in ('one','two'):f.repository(repo)
        a=f.commit('one',{'same':b'bytes'},label='identical');b=f.commit('two',{'same':b'bytes'},label='identical')
        self.assertEqual(a,b)
        c=self.calculate(f.spec([('first','one',(a,)),('second','two',(b,))]))
        self.assertEqual(len(c.commits),2);self.assertEqual({x.repository for x in c.objects},{'one','two'})
        self.assertEqual(len(c.objects),6)

    def test_nested_cycle_detection_is_distinct_from_shared_dedup(self):
        from historycrate.closure import _check_materialization_graph
        from historycrate.model import GitlinkRecord
        a=('one','a'*40);b=('two','b'*40)
        links=[GitlinkRecord(*a,'child','child','0'*64,*b),GitlinkRecord(*b,'parent','parent','0'*64,*a)]
        with self.assertRaises(CrateError) as ctx:_check_materialization_graph({a,b},links,16)
        self.assertEqual(ctx.exception.code,'RECURSIVE_GITLINK_CYCLE')
        _check_materialization_graph({a,b},links[:1]*2,16)

    def test_explanations_distinguish_roots_parents_and_gitlink_reasons(self):
        from historycrate.closure import explain_inclusion
        f=self.fixture;f.repository('main');f.repository('child')
        child=f.commit('child',{'x':b'child'});base=f.commit('main',{'x':b'base'})
        tip=f.commit('main',{'.gitmodules':modules(('dep','dep','../child')),'dep':(0o160000,child)},(base,))
        c=self.calculate(f.spec([('release','main',(tip,))],[('main','dep','../child','child')]))
        self.assertEqual(explain_inclusion(c,'main',tip)['reasons'],[{'kind':'selected-root','root':'release'}])
        self.assertEqual(explain_inclusion(c,'main',base)['reasons'],[{'kind':'parent','repository':'main','commit':tip}])
        reasons=explain_inclusion(c,'child',child)['reasons'];self.assertEqual(reasons[0]['kind'],'gitlink');self.assertEqual(reasons[0]['path'],'dep')
        self.assertNotIn('../child',str(reasons))
        with self.assertRaises(CrateError):explain_inclusion(c,'main','f'*40)

    def test_lowered_metadata_and_pointer_budgets_refuse(self):
        f=self.fixture;f.repository('main')
        sha=hashlib.sha256(b'x').hexdigest();pointer=f'version https://git-lfs.github.com/spec/v1\noid sha256:{sha}\nsize 1\n'.encode()
        tip=f.commit('main',{'.gitattributes':b'*.bin filter=lfs -text\n','.gitmodules':modules(('old','gone','../old')),'x.bin':pointer})
        for resource in ('gitmodules_bytes','gitattributes_bytes','pointer_bytes','lfs_payload_bytes'):
            with self.subTest(resource=resource),self.assertRaises(CrateError) as ctx:self.calculate(f.spec([('release','main',(tip,))],limits=Limits().lower({resource:0})))
            self.assertEqual(ctx.exception.exit_code,5)
