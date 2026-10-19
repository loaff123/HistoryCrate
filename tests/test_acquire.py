from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.model import RepoSpec, Spec
from historycrate.native import Job, qualify_toolchain
from tests.fixtures.git_stores import store, loose, history, pack, canonical, tree_bytes, commit_bytes, hashes

ROOT = Path(__file__).resolve().parents[1]


class AcquireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(TEST_GIT, TEST_LFS, Limits())

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.acquire'), 'read-only source acquisition is not implemented')
        from historycrate import acquire
        self.a = acquire
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = store(self.base / 'source')
        self.repo = RepoSpec('source', self.source, self.source / 'lfs/objects')
        self.job = Job(Limits(), self.tools, output_parent=self.base, source_paths=(self.source,))
        self.job.__enter__()
        self.addCleanup(self.job.__exit__, None, None, None)

    def test_fresh_copies_ignore_indexes_and_source_config(self):
        commit, tree, blob = history(self.source)
        (self.source / 'index').write_bytes(b'inert invalid index')
        trap = self.base / 'trap'
        with (self.source / 'config').open('a') as out:
            out.write(f'[core]\nworktree = /never-follow\nfsmonitor = touch {trap}\n[filter "evil"]\nclean = touch {trap}\n[credential]\nhelper = !touch {trap}\n[include-not-a-directive]\nfoo = inert\n')
        before = hashes(self.source)
        acquired = self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(hashes(self.source), before)
        self.assertFalse(trap.exists())
        self.assertEqual(acquired.id, 'source')
        self.assertEqual(len(acquired.source_inventory_digest), 64)
        self.assertFalse((acquired.stage_git_dir / 'index').exists())
        self.assertNotIn('never-follow', (acquired.stage_git_dir / 'config').read_text())
        self.assertNotEqual((self.source / 'objects' / blob[:2] / blob[2:]).stat().st_ino,
                            (acquired.stage_git_dir / 'objects' / blob[:2] / blob[2:]).stat().st_ino)
        self.assertEqual([p for p in (acquired.stage_git_dir / 'refs').rglob('*') if p.is_file()], [])
        for command in self.job.native.records:
            self.assertNotIn(str(self.source), command['argv'])

    def test_repository_markers_refused(self):
        for marker in ('shallow', 'commondir', 'worktrees', 'info/grafts', 'objects/info/alternates',
                       'objects/info/http-alternates', 'objects/pack/pack-' + 'a' * 40 + '.promisor',
                       'refs/replace', 'reftable'):
            with self.subTest(marker=marker):
                path = self.source / marker
                path.parent.mkdir(exist_ok=True, parents=True)
                path.write_bytes(b'')
                before = hashes(self.source)
                with self.assertRaises(CrateError) as caught:
                    self.a.acquire_repository(self.repo, self.job)
                self.assertEqual(caught.exception.code, 'UNSUPPORTED_REPOSITORY')
                self.assertEqual(hashes(self.source), before)
                path.unlink()

    def test_packed_replacement_ref_refused(self):
        (self.source / 'packed-refs').write_text('a' * 40 + ' refs/replace/' + 'b' * 40 + '\n')
        with self.assertRaises(CrateError) as caught:
            self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.code, 'UNSUPPORTED_REPOSITORY')

    def test_inert_config_structural_refusals(self):
        original = (self.source / 'config').read_text()
        cases = ('[include]\npath = /never-read\n', '[includeIf "onbranch:main"]\npath = /never-read\n',
                 '[extensions]\nobjectformat = sha256\n', '[extensions]\nrefStorage = reftable\n',
                 '[extensions]\nworktreeConfig = true\n', '[remote "origin"]\npromisor = false\n',
                 '[remote "origin"]\npartialclonefilter = blob:none\n',
                 '[core]\nrepositoryformatversion = 1\n', '[core]\nbare = true\n')
        for extra in cases:
            with self.subTest(extra=extra):
                (self.source / 'config').write_text(original + extra)
                before = hashes(self.source)
                with self.assertRaises(CrateError) as caught:
                    self.a.acquire_repository(self.repo, self.job)
                self.assertEqual(caught.exception.code, 'UNSUPPORTED_REPOSITORY')
                self.assertEqual(hashes(self.source), before)

    def test_valid_cross_pack_links_survive_and_source_indexes_are_ignored(self):
        blob_data = b'cross-pack\n'
        blob = canonical('blob', blob_data)[0]
        tree_data = tree_bytes(((0o100644, b'file', blob),))
        tree = canonical('tree', tree_data)[0]
        commit_data = commit_bytes(tree)
        commit = canonical('commit', commit_data)[0]
        for kind, data in (('blob', blob_data), ('tree', tree_data), ('commit', commit_data)):
            path = pack(self.source, [(kind, data)])
            path.with_suffix('.idx').write_bytes(b'untrusted source index ignored')
        before = hashes(self.source)
        acquired = self.a.acquire_repository(self.repo, self.job)
        from historycrate.objects import ObjectReader
        self.assertEqual(ObjectReader(acquired, self.job).commit(commit).tree, tree)
        self.assertEqual(hashes(self.source), before)
        self.assertEqual(len(list((acquired.stage_git_dir / 'objects/pack').glob('*.idx'))), 3)

    def test_missing_delta_base_refused(self):
        pack(self.source, [('blob', b'\x01\x01\x01x')], missing_base='a' * 40)
        with self.assertRaises(CrateError) as caught:
            self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.exit_code, 4)

    def test_unrelated_corruption_is_conservative_failure(self):
        history(self.source)
        path = self.source / 'objects/aa' / ('b' * 38)
        path.parent.mkdir()
        path.write_bytes(b'not zlib')
        before = hashes(self.source)
        with self.assertRaises(CrateError) as caught:
            self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.exit_code, 4)
        self.assertEqual(hashes(self.source), before)

    def test_source_change_blocks_without_retry(self):
        history(self.source)
        original = self.a._copy_file
        calls = []
        def change(*args, **kwargs):
            result = original(*args, **kwargs)
            calls.append(1)
            (self.source / 'new-file').write_bytes(b'raced')
            return result
        with patch.object(self.a, '_copy_file', side_effect=change):
            with self.assertRaises(CrateError) as caught:
                self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
        self.assertEqual(caught.exception.exit_code, 4)
        self.assertGreater(len(calls), 0)
        self.assertNotIn('source', self.job.native.repositories)

    def test_source_object_symlink_hardlink_and_special_refused(self):
        for variant in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(variant=variant):
                path = self.source / 'objects/ab' / ('c' * 38)
                path.parent.mkdir(exist_ok=True)
                target = self.base / 'target'
                target.write_bytes(b'data')
                if variant == 'symlink': path.symlink_to(target)
                elif variant == 'hardlink': os.link(target, path)
                else: os.mkfifo(path)
                with self.assertRaises(CrateError): self.a.acquire_repository(self.repo, self.job)
                path.unlink()

    def test_unknown_object_and_pack_entries_refused(self):
        for relative in ('objects/aa/garbage', 'objects/pack/not-a-pack', 'objects/XX'):
            with self.subTest(relative=relative):
                path = self.source / relative
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(b'')
                with self.assertRaises(CrateError): self.a.acquire_repository(self.repo, self.job)
                path.unlink()
                if path.parent.name == 'aa': path.parent.rmdir()

    def test_absorbed_git_directory_works_and_nonstandard_nonbare_refused(self):
        absorbed = store(self.base / 'work/.git/modules/child', bare=False)
        (absorbed / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\nworktree = ../../../../child\n')
        commit, _, _ = history(absorbed)
        acquired = self.a.acquire_repository(RepoSpec('child', absorbed, absorbed / 'lfs/objects'), self.job)
        from historycrate.objects import ObjectReader
        self.assertEqual(ObjectReader(acquired, self.job).commit(commit).oid, commit)
        (self.source / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = false\nworktree = /never-follow\n')
        with self.assertRaises(CrateError): self.a.acquire_repository(self.repo, self.job)

    def test_pool_is_lazy_and_preserves_repository_identity(self):
        history(self.source)
        missing = RepoSpec('unused', self.base / 'absent', self.base / 'absent-lfs')
        spec = Spec(1, (self.repo, missing), (), (), Limits())
        pool = self.a.RepositoryPool(spec, self.job)
        self.assertEqual(self.job.native.repositories, {})
        first = pool.get('source')
        self.assertIs(pool.get('source'), first)
        self.assertEqual(set(self.job.native.repositories), {'source'})
        with self.assertRaises(CrateError): pool.get('unknown')

    def test_source_copy_budget_is_enforced_before_native_init(self):
        history(self.source)
        with Job(Limits().lower({'source_git_bytes': 1}), self.tools, output_parent=self.base) as job:
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, job)
            self.assertEqual(caught.exception.exit_code, 5)
            self.assertEqual(job.native.repositories, {})

    def test_removed_object_during_open_reports_source_changed(self):
        history(self.source)
        original = self.a._copy_file
        removed = []
        def change(root_fd, relative, *args, **kwargs):
            if relative.startswith('objects/') and not removed:
                (self.source / relative).unlink()
                removed.append(relative)
            return original(root_fd, relative, *args, **kwargs)
        with patch.object(self.a, '_copy_file', side_effect=change):
            with self.assertRaises(CrateError) as caught:
                self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
        self.assertEqual(caught.exception.exit_code, 4)
        self.assertEqual(len(removed), 1)

    def test_source_directory_replacement_is_not_followed(self):
        history(self.source)
        original = self.a._copy_file
        changed = []
        def change(*args, **kwargs):
            result = original(*args, **kwargs)
            if not changed:
                self.source.rename(self.base / 'old-source')
                self.source.mkdir()
                (self.source / 'sentinel').write_bytes(b'preserve replacement')
                changed.append(True)
            return result
        with patch.object(self.a, '_copy_file', side_effect=change):
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
        self.assertEqual((self.source / 'sentinel').read_bytes(), b'preserve replacement')

    def test_pool_refuses_duplicate_repository_identity(self):
        history(self.source)
        duplicate = RepoSpec('duplicate', self.source, self.source / 'lfs/objects')
        pool = self.a.RepositoryPool(Spec(1, (self.repo, duplicate), (), (), Limits()), self.job)
        pool.get('source')
        with self.assertRaises(CrateError) as caught: pool.get('duplicate')
        self.assertEqual(caught.exception.code, 'DUPLICATE_REPOSITORY_IDENTITY')

    def test_pool_distinct_repositories_keep_identical_objects_separate(self):
        commit, _, _ = history(self.source)
        second = store(self.base / 'other')
        self.assertEqual(history(second)[0], commit)
        repo = RepoSpec('other', second, second / 'lfs/objects')
        pool = self.a.RepositoryPool(Spec(1, (self.repo, repo), (), (), Limits()), self.job)
        self.assertNotEqual(pool.get('source').stage_git_dir, pool.get('other').stage_git_dir)
        self.assertEqual(set(pool.acquired), {'source', 'other'})

    def test_pool_refuses_object_cache_overlap(self):
        history(self.source)
        repo = RepoSpec('source', self.source, self.source / 'objects')
        pool = self.a.RepositoryPool(Spec(1, (repo,), (), (), Limits()), self.job)
        with self.assertRaises(CrateError) as caught: pool.get('source')
        self.assertEqual(caught.exception.code, 'PATH_OVERLAP')

    def test_pool_refuses_dangling_cache_ancestor_symlink(self):
        history(self.source)
        (self.source / 'lfs').symlink_to(self.base / 'absent')
        pool = self.a.RepositoryPool(Spec(1, (self.repo,), (), (), Limits()), self.job)
        with self.assertRaises(CrateError) as caught: pool.get('source')
        self.assertEqual(caught.exception.exit_code, 3)

    def test_empty_store_accepts_only_unborn_and_no_reference_notices(self):
        acquired = self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(acquired.id, 'source')
        from historycrate.process import ProcessResult
        original = self.job.native._execute
        def warning(*args, **kwargs):
            result = original(*args, **kwargs)
            return ProcessResult(result.stdout, result.stderr + b'warning: unsafe object\n', result.returncode, result.observations)
        with patch.object(self.job.native, '_execute', side_effect=warning):
            with self.assertRaises(CrateError) as caught:
                self.job.native.run('fsck_acquired', {'repo': 'source'})
        self.assertEqual(caught.exception.code, 'NATIVE_INTEGRITY_DIAGNOSTIC')

    def test_metadata_size_limit_blocks_before_parse(self):
        with Job(Limits().lower({'config_bytes': 1}), self.tools, output_parent=self.base) as job:
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, job)
            self.assertEqual(caught.exception.exit_code, 5)
            self.assertEqual(job.native.records, [])

    def test_observation_threshold_is_not_raised(self):
        history(self.source)
        with Job(Limits().lower({'observation_entries': 2}), self.tools, output_parent=self.base) as job:
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, job)
            self.assertEqual(caught.exception.exit_code, 5)
            self.assertEqual(job.limits.observation_entries, 2)
            self.assertEqual(Limits().observation_entries, 4096)

    def test_missing_graph_objects_have_typed_diagnostics(self):
        for missing, expected in (('blob', 'MISSING_BLOB'), ('tree', 'MISSING_TREE'), ('parent', 'MISSING_PARENT')):
            with self.subTest(missing=missing):
                source = store(self.base / ('missing-' + missing))
                commit, tree, blob = history(source)
                oid = {'blob': blob, 'tree': tree, 'parent': 'a' * 40}[missing]
                if missing == 'parent':
                    loose(source, 'commit', commit_bytes(tree, (oid,)))
                else:
                    (source / 'objects' / oid[:2] / oid[2:]).unlink()
                repo = RepoSpec('missing-' + missing, source, source / 'lfs/objects')
                with self.assertRaises(CrateError) as caught: self.a.acquire_repository(repo, self.job)
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(caught.exception.context['oid'], oid)

    def test_acquisition_reserves_space_and_combined_existing_scratch(self):
        from types import SimpleNamespace
        with patch('os.fstatvfs', return_value=SimpleNamespace(f_bavail=1, f_frsize=1)):
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.code, 'INSUFFICIENT_SPACE')
        self.assertEqual(self.job.native.records, [])
        with Job(Limits().lower({'combined_bytes': 10}), self.tools, output_parent=self.base) as job:
            (job.root / 'existing').write_bytes(b'already occupies storage')
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, job)
            self.assertEqual(caught.exception.exit_code, 5)
            self.assertEqual(job.native.records, [])

    def test_copy_loop_checks_watchdog_between_chunks(self):
        import time
        original_read = os.read
        original_clock = time.monotonic
        future = [False]
        inode = (self.source / 'config').stat().st_ino
        def read(fd, size):
            block = original_read(fd, size)
            if os.fstat(fd).st_ino == inode: future[0] = True
            return block
        def now():
            return original_clock() + (self.job.limits.job_wall_seconds + 1 if future[0] else 0)
        with patch('os.read', side_effect=read), patch('time.monotonic', side_effect=now):
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.exit_code, 5)
        # The controller must stop before launching parsing, after source read.
        self.assertEqual(self.job.native.records, [])
        self.assertTrue(getattr(self.job, 'controller_observations', ()))

    def test_newly_admitted_source_cannot_contain_selected_tool(self):
        from dataclasses import replace
        history(self.source)
        tools = replace(self.tools, git_lfs=self.source / 'tool/git-lfs')
        with Job(Limits(), tools, output_parent=self.base) as job:
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, job)
            self.assertEqual(caught.exception.code, 'SOURCE_PATH_CANNOT_BE_TOOL')
            self.assertEqual(job.native.records, [])

    def test_direct_acquisition_requires_absolute_paths_and_safe_identity(self):
        for repo in (RepoSpec('source', Path('relative'), Path('/cache')),
                     RepoSpec('source', self.source, Path('relative-cache')),
                     RepoSpec('SOURCE', self.source, self.source / 'lfs/objects')):
            with self.subTest(repo=repo), self.assertRaises(CrateError) as caught:
                self.a.acquire_repository(repo, self.job)
            self.assertEqual(caught.exception.exit_code, 2)
        self.assertEqual(self.job.native.records, [])

    def test_disk_full_aborts_copy_as_resource_failure(self):
        import errno
        with patch.object(self.a, '_copy_file', side_effect=OSError(errno.ENOSPC, 'authored disk-full injection')):
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(caught.exception.code, 'INSUFFICIENT_SPACE')
        self.assertEqual(self.job.native.repositories, {})

    def test_all_acquired_objects_obey_lowered_count_in_packs(self):
        pack(self.source, [('blob', b'one'), ('blob', b'two'), ('blob', b'three')])
        with Job(Limits().lower({'git_objects': 2}), self.tools, output_parent=self.base) as job:
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, job)
            self.assertEqual(caught.exception.exit_code, 5)
            self.assertEqual(caught.exception.context['resource'], 'git_objects')

    def test_duplicate_native_inventory_oid_is_refused(self):
        from dataclasses import replace
        history(self.source)
        original = self.job.native.run
        def duplicate(operation, parameters, stdin=b''):
            result = original(operation, parameters, stdin)
            if operation == 'list_objects':
                result = replace(result, stdout=result.stdout + result.stdout.splitlines(keepends=True)[0])
            return result
        with patch.object(self.job.native, 'run', side_effect=duplicate):
            with self.assertRaises(CrateError) as caught: self.a.acquire_repository(self.repo, self.job)
        self.assertEqual(caught.exception.code, 'INVALID_OBJECT_INVENTORY')
