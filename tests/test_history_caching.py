"""Original repeated-history cache fixtures; all object reads use native Git."""
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import io
from dataclasses import FrozenInstanceError
from pathlib import Path
import tempfile
import unittest

from historycrate.acquire import acquire_repository, recheck_sources
from historycrate.errors import CrateError
from historycrate.limits import Budget, Limits
from historycrate.metadata import read_gitmodules
from historycrate.model import RepoSpec
from historycrate.native import Job, qualify_toolchain
from historycrate.objects import ObjectReader
from tests.fixtures.git_stores import store, history, loose, tree_bytes, commit_bytes

ROOT = Path(__file__).resolve().parents[1]


class HistoryCachingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(TEST_GIT, TEST_LFS, Limits())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='historycrate-cache-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = store(self.base/'source')
        self.commit, self.tree, self.blob = history(self.source)
        self.job = Job(Limits(), self.tools, output_parent=self.base)
        self.job.__enter__()
        self.addCleanup(self.job.__exit__, None, None, None)
        self.acquired = acquire_repository(RepoSpec('main', self.source, self.source/'lfs/objects'), self.job)
        self.reader = ObjectReader(self.acquired, self.job)

    def commands(self):
        return len(self.job.native.records)

    def test_repeated_commit_and_tree_need_one_native_read_each(self):
        before = self.commands()
        commit = self.reader.commit(self.commit)
        tree = self.reader.tree(self.tree)
        self.assertEqual(self.commands()-before, 2)
        for _ in range(3):
            self.assertIs(self.reader.commit(self.commit), commit)
            self.assertIs(self.reader.tree(self.tree), tree)
        self.assertEqual(self.commands()-before, 2)
        with self.assertRaises(FrozenInstanceError):
            commit.tree = '0'*40
        with self.assertRaises(FrozenInstanceError):
            tree[0].name = b'changed'

    def test_new_reader_cache_hits_still_inventory_every_object(self):
        first = (self.reader.commit(self.commit), self.reader.tree(self.tree))
        before = self.commands()
        second = ObjectReader(self.acquired, self.job)
        self.assertIs(second.commit(self.commit), first[0])
        self.assertIs(second.tree(self.tree), first[1])
        self.assertEqual(self.commands(), before)
        self.assertEqual(second.records, self.reader.records)
        self.assertEqual(self.job.budget.used['git_objects'], 2)

    def test_cache_hits_charge_new_budget_unique_identities(self):
        self.reader.commit(self.commit); self.reader.tree(self.tree)
        self.job.budget = Budget(Limits().lower({'git_objects': 1}))
        before = self.commands()
        self.reader.commit(self.commit); self.reader.commit(self.commit)
        self.assertEqual(self.commands(), before)
        self.assertEqual(self.job.budget.used['git_objects'], 1)
        with self.assertRaises(CrateError) as caught:
            self.reader.tree(self.tree)
        self.assertEqual(caught.exception.context['resource'], 'git_objects')
        self.assertEqual(self.commands(), before)

    def test_cached_info_also_charges_a_replaced_budget(self):
        self.reader.info(self.blob)
        self.job.budget = Budget(Limits().lower({'git_objects': 0}))
        with self.assertRaises(CrateError) as caught:
            self.reader.info(self.blob)
        self.assertEqual(caught.exception.context['resource'], 'git_objects')

    def test_lru_entry_limit_evicts_least_recent_not_recently_hit(self):
        # Only one commit is demanded; the cache also caps entries by this limit.
        self.job.limits = self.job.limits.lower({'commits': 2})
        self.reader.commit(self.commit); self.reader.tree(self.tree)
        self.reader.commit(self.commit)
        extra = loose(self.acquired.stage_git_dir, 'tree', b'')
        self.reader.tree(extra)
        before = self.commands()
        self.reader.commit(self.commit)
        self.assertEqual(self.commands(), before)
        self.reader.tree(self.tree)
        self.assertEqual(self.commands(), before+1)
        self.assertEqual(set(self.reader.records), {self.commit, self.tree, extra})
        self.assertEqual(self.job.budget.used['git_objects'], 3)

    def test_byte_admission_skips_large_parsed_tree_but_keeps_small_commit(self):
        self.job.limits = self.job.limits.lower({'captured_bytes': 2000})
        self.reader.commit(self.commit)
        large = loose(self.acquired.stage_git_dir, 'tree', tree_bytes(tuple(
            (0o100644, f'file-{i:04d}'.encode(), self.blob) for i in range(30))))
        self.reader.tree(large)
        before = self.commands()
        self.reader.commit(self.commit)
        self.assertEqual(self.commands(), before)
        self.reader.tree(large)
        self.assertEqual(self.commands(), before+1)

    def test_lowered_tree_limit_is_enforced_on_cache_hit(self):
        result = self.reader.tree(self.tree)
        self.assertIs(self.reader.tree(self.tree), result)
        self.job.limits = self.job.limits.lower({'commit_path_visits': 0})
        with self.assertRaises(CrateError) as caught:
            self.reader.tree(self.tree)
        self.assertEqual(caught.exception.context['resource'], 'commit_path_visits')

    def test_fresh_phase_rereads_verified_commit_and_tree(self):
        from historycrate.packet import _phase
        first = (self.reader.commit(self.commit), self.reader.tree(self.tree))
        self.assertIs(self.reader.commit(self.commit), first[0])
        phase = _phase(self.job, self.job.root/'fresh-cache-test')
        acquired = acquire_repository(RepoSpec('main', self.source, self.source/'lfs/objects'), phase)
        reader = ObjectReader(acquired, phase)
        before = self.commands()
        actual = (reader.commit(self.commit), reader.tree(self.tree))
        self.assertEqual(actual, first)
        self.assertIsNot(actual[0], first[0])
        self.assertIsNot(actual[1], first[1])
        self.assertEqual(self.commands(), before+2)
        self.assertEqual(phase.budget.used['git_objects'], 2)

    def test_source_mutation_still_refused_after_cache_hits(self):
        first = self.reader.commit(self.commit)
        (self.source/'refs/heads/main').write_text('0'*40+'\n')
        self.assertIs(self.reader.commit(self.commit), first)
        with self.assertRaises(CrateError) as caught:
            recheck_sources(self.job)
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')

    def test_blobs_are_never_payload_cached(self):
        self.reader.commit(self.commit)
        self.assertIs(self.reader.commit(self.commit), self.reader.commit(self.commit))
        before = self.commands()
        self.assertEqual(self.reader.read(self.blob), ('blob', b'hello\n'))
        output = io.BytesIO()
        self.reader.copy_blob(self.blob, output)
        self.assertEqual(output.getvalue(), b'hello\n')
        self.assertEqual(self.commands(), before+2)

    def test_repeated_gitmodules_are_parsed_once_and_caller_cannot_poison(self):
        raw = b'[submodule "old"]\npath = gone\nurl = ../old\n'
        blob = loose(self.acquired.stage_git_dir, 'blob', raw)
        tree = loose(self.acquired.stage_git_dir, 'tree', tree_bytes(((0o100644, b'.gitmodules', blob),)))
        tip = loose(self.acquired.stage_git_dir, 'commit', commit_bytes(tree))
        first = read_gitmodules(self.reader, tip)
        self.assertEqual(first, {'gone': ('old', '../old')})
        first.clear()
        before = self.commands()
        for reader in (self.reader, ObjectReader(self.acquired, self.job)):
            self.assertEqual(read_gitmodules(reader, tip), {'gone': ('old', '../old')})
            self.assertEqual(set(reader.records) & {tip, tree, blob}, {tip, tree, blob})
        self.assertEqual(self.commands(), before)

    def test_original_repeated_tree_history_native_command_count(self):
        from historycrate.acquire import RepositoryPool
        from historycrate.closure import build_closure
        from historycrate.model import RootSpec, Spec
        source = store(self.base/'repeated')
        blob = loose(source, 'blob', b'original repeated fixture\n')
        modules = loose(source, 'blob', b'[submodule "old"]\npath=gone\nurl=../old\n')
        subtree = loose(source, 'tree', tree_bytes(((0o100644, b'file', blob),)))
        tree = loose(source, 'tree', tree_bytes(((0o100644, b'.gitmodules', modules),
                                               (0o40000, b'dir', subtree))))
        commits = []
        for i in range(12):
            commits.append(loose(source, 'commit', commit_bytes(tree, tuple(commits[-1:]),
                                                                 f'original {i}\n'.encode())))
        (source/'refs/heads/main').write_text(commits[-1]+'\n')
        spec = Spec(1, (RepoSpec('repeated', source, source/'lfs/objects'),),
                    (RootSpec('release', 'repeated', (commits[-1],)),), (), Limits())
        with Job(spec.limits, self.tools, output_parent=self.base) as job:
            closure = build_closure(spec, RepositoryPool(spec, job), job)
            reads = sum('cat-file' in r['argv'] and '--batch' in r['argv'] for r in job.native.records)
            print(f'ORIGINAL_REPEATED_TREE native_commands={len(job.native.records)} object_reads={reads}')
            self.assertEqual({c.oid for c in closure.commits}, set(commits))
            self.assertEqual({o.oid for o in closure.objects}, {*commits, tree, subtree, blob, modules})
            self.assertEqual(job.budget.used['commit_path_visits'], 36)
            self.assertEqual(job.budget.used['git_objects'], 16)
            # 12 commits, 2 trees, 2 blob-info reads and one metadata-byte read.
            self.assertEqual(reads, 17)

    def test_byte_limit_evicts_old_entry_and_retains_exactly_one(self):
        self.job.limits = self.job.limits.lower({'captured_bytes': 2000})
        self.reader.commit(self.commit)
        tree = self.reader.tree(self.tree)
        before = self.commands()
        self.assertIs(self.reader.tree(self.tree), tree)
        self.assertEqual(self.commands(), before)
        self.reader.commit(self.commit)
        self.assertEqual(self.commands(), before+1)
        cache = self.job._parsed_object_cache
        self.assertLessEqual(cache.used_bytes, 2000)
        self.assertEqual(len(cache.entries), 1)

    def test_canonical_hash_failure_is_not_admitted_to_cache(self):
        import zlib
        from tests.fixtures.git_stores import canonical
        good = commit_bytes(self.tree, message=b'uncached canonical fixture\n')
        oid, canonical_bytes = canonical('commit', good)
        target = self.acquired.stage_git_dir/'objects'/oid[:2]/oid[2:]
        target.parent.mkdir(exist_ok=True)
        bad = good.replace(b'canonical fixture', b'canonical corrupt')
        target.write_bytes(zlib.compress(canonical('commit', bad)[1]))
        with self.assertRaises(CrateError) as caught:
            self.reader.commit(oid)
        self.assertEqual(caught.exception.code, 'OBJECT_HASH_MISMATCH')
        self.assertNotIn(oid, self.reader.records)
        target.write_bytes(zlib.compress(canonical_bytes))
        result = self.reader.commit(oid)
        before = self.commands()
        self.assertIs(self.reader.commit(oid), result)
        self.assertEqual(self.commands(), before)

    def test_parser_errors_are_retried_and_never_cached(self):
        self.reader.commit(self.commit)
        self.assertIs(self.reader.commit(self.commit), self.reader.commit(self.commit))
        for kind, data, method, code in (
                ('commit', b'tree malformed\n\n', self.reader.commit, 'INVALID_COMMIT'),
                ('tree', b'100644 missing-nul', self.reader.tree, 'INVALID_TREE')):
            oid = loose(self.acquired.stage_git_dir, kind, data)
            before = self.commands()
            for _ in range(2):
                with self.assertRaises(CrateError) as caught:
                    method(oid)
                self.assertEqual(caught.exception.code, code)
            self.assertEqual(self.commands(), before+2)

    def test_cached_oid_still_has_precise_wrong_type_and_missing_errors(self):
        commit = self.reader.commit(self.commit)
        self.assertIs(self.reader.commit(self.commit), commit)
        with self.assertRaises(CrateError) as caught:
            self.reader.tree(self.commit)
        self.assertEqual(caught.exception.code, 'OBJECT_TYPE_MISMATCH')
        for method, code in ((self.reader.commit, 'MISSING_COMMIT'), (self.reader.tree, 'MISSING_TREE')):
            with self.assertRaises(CrateError) as caught:
                method('a'*40)
            self.assertEqual(caught.exception.code, code)

    def test_same_oid_in_another_repository_is_fresh_and_separately_charged(self):
        first = self.reader.commit(self.commit)
        self.assertIs(self.reader.commit(self.commit), first)
        acquired = acquire_repository(RepoSpec('second', self.source, self.source/'lfs/objects'), self.job)
        second = ObjectReader(acquired, self.job)
        before = self.commands()
        actual = second.commit(self.commit)
        self.assertEqual(actual.repository, 'second')
        self.assertEqual(actual.oid, first.oid)
        self.assertIsNot(actual, first)
        self.assertEqual(self.commands(), before+1)
        self.assertEqual(self.job.budget.used['git_objects'], 2)

    def test_cache_hit_checks_deadline_and_staging_directory_identity(self):
        import time
        first = self.reader.commit(self.commit)
        self.assertIs(self.reader.commit(self.commit), first)
        started = self.job.native.started
        self.job.native.started = time.monotonic()-self.job.limits.job_wall_seconds-1
        with self.assertRaises(CrateError) as caught:
            self.reader.commit(self.commit)
        self.assertEqual(caught.exception.context['resource'], 'job_wall_seconds')
        self.job.native.started = started
        stage = self.acquired.stage_git_dir
        stage.rename(stage.with_name('original-staging'))
        stage.mkdir(mode=0o700)
        with self.assertRaises(CrateError) as caught:
            self.reader.commit(self.commit)
        self.assertEqual(caught.exception.code, 'STAGING_CHANGED')

    def test_lowered_gitmodules_limit_is_enforced_after_successful_cache_hit(self):
        raw = b'[submodule "old"]\npath=gone\nurl=../old\n'
        blob = loose(self.acquired.stage_git_dir, 'blob', raw)
        tree = loose(self.acquired.stage_git_dir, 'tree', tree_bytes(((0o100644, b'.gitmodules', blob),)))
        tip = loose(self.acquired.stage_git_dir, 'commit', commit_bytes(tree))
        first = read_gitmodules(self.reader, tip)
        before = self.commands()
        self.assertEqual(read_gitmodules(self.reader, tip), first)
        self.assertEqual(self.commands(), before)
        self.job.limits = self.job.limits.lower({'gitmodules_bytes': len(raw)-1})
        with self.assertRaises(CrateError) as caught:
            read_gitmodules(self.reader, tip)
        self.assertEqual(caught.exception.context['resource'], 'gitmodules_bytes')

    def test_cached_gitmodules_revalidates_lowered_path_limits(self):
        raw = b'[submodule "old"]\npath=gone\nurl=../old\n'
        blob = loose(self.acquired.stage_git_dir, 'blob', raw)
        tree = loose(self.acquired.stage_git_dir, 'tree', tree_bytes(((0o100644, b'.gitmodules', blob),)))
        tip = loose(self.acquired.stage_git_dir, 'commit', commit_bytes(tree))
        self.assertEqual(read_gitmodules(self.reader, tip), {'gone': ('old', '../old')})
        self.job.limits = self.job.limits.lower({'path_bytes': 3})
        with self.assertRaises(CrateError) as caught:
            read_gitmodules(self.reader, tip)
        self.assertEqual(caught.exception.code, 'BUDGET_EXCEEDED')
        self.assertEqual(caught.exception.context['resource'], 'path')


if __name__ == '__main__':
    unittest.main()
