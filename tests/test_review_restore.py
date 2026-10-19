"""Independent Task 7 acceptance and cache-boundary probes on original fixtures.

Expected histories, trees, indexes, bytes and status come from native Git and
explicit fixture declarations, never the production graph/manifest parsers.
"""
from dataclasses import FrozenInstanceError
import hashlib
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from historycrate.errors import CrateError
from historycrate.limits import Budget, Limits
from historycrate.native import Job, qualify_toolchain
from historycrate.packet import build_packet, verify_packet
from historycrate.restore import restore_verified
from tests.fixtures.histories import HistoryBuilder, modules, native, inventory
from tests.toolchain import GIT, LFS


def native_tree(source, commit):
    result = {}
    for entry in native(source, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if entry:
            header, path = entry.split(b'\t', 1)
            mode, kind, oid = header.split()
            result[path.decode()] = (int(mode, 8), kind.decode(), oid.decode())
    return result


def interrupt_after_return(real_function, caller_function, triggered):
    """Raise once on the actual caller's first line after a successful return."""
    import inspect
    import sys
    previous_trace = sys.gettrace()
    def wrapped(*args, **kwargs):
        result = real_function(*args, **kwargs)
        caller = inspect.currentframe().f_back
        while caller and caller.f_globals.get('__name__') != caller_function.__module__:
            caller = caller.f_back
        if caller is None:
            raise AssertionError('expected caller frame was absent')
        def trace(frame, event, arg):
            if frame is caller and event == 'line':
                triggered.append(frame.f_lineno)
                sys.settrace(previous_trace)
                frame.f_trace = previous_trace
                raise KeyboardInterrupt('injected successful-return handoff interruption')
            return trace
        sys.settrace(trace)
        caller.f_trace = trace
        return result
    return wrapped


class ReviewRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(GIT, LFS, Limits())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='historycrate-independent-restore-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.f = HistoryBuilder(self.root)
        for repository in ('main', 'child', 'leaf'):
            self.f.repository(repository)
        self.payload = b'original independent payload\0\n'
        self.digest = hashlib.sha256(self.payload).hexdigest()
        pointer = f'version https://git-lfs.github.com/spec/v1\noid sha256:{self.digest}\nsize {len(self.payload)}\n'.encode()
        self.leaf = self.f.commit('leaf', {'leaf': b'leaf\n'})
        self.child = self.f.commit('child', {
            '.gitmodules': modules(('nested', 'nested', '../leaf')),
            '.gitattributes': b'*.bin filter=lfs -text\n*.txt text eol=crlf\n',
            'nested': (0o160000, self.leaf),
            "dir/space apostrophe'.bin": (0o100755, self.f.blob('child', pointer)),
            'dir/empty.bin': b'', ':wq': b'literal colon\n', '-leading': b'literal dash\n',
            'dir/text.txt': b'one\ntwo\n', 'pointer-literal': pointer,
        })
        cache = self.f.repos['child']/'lfs/objects'/self.digest[:2]/self.digest[2:4]/self.digest
        cache.parent.mkdir(parents=True)
        cache.write_bytes(self.payload)
        self.first = self.f.commit('main', {'.gitmodules': modules(('dep', 'old', '../child')),
                                           'old': (0o160000, self.child), 'plain': b'plain\n'})
        self.absent = self.f.commit('main', {'.gitmodules': modules(('dep', 'old', '../child')),
                                            'old': b'now regular\n', 'plain': b'plain\n'}, (self.first,))
        self.tip = self.f.commit('main', {'.gitmodules': modules(('dep', 'new', '../changed'), ('shared', 'shared', '../child')),
                                         'new': (0o160000, self.child), 'shared': (0o160000, self.child),
                                         'plain': b'plain\n'}, (self.absent,))
        self.selected_tip = self.tip
        self.routes = {('main', 'old'): 'child', ('main', 'new'): 'child', ('main', 'shared'): 'child', ('child', 'nested'): 'leaf'}
        self.spec = self.f.spec([('release', 'main', (self.tip,))], [
            ('main', 'old', '../child', 'child'), ('main', 'new', '../changed', 'child'),
            ('main', 'shared', '../child', 'child'), ('child', 'nested', '../leaf', 'leaf')])

    def job(self):
        return Job(self.spec.limits, self.tools, source_paths=tuple(self.f.repos.values()))

    def assert_native_restore(self, output, commit, staging_path=None):
        pending = [(output, 'main', commit, '')]
        expected_links = {}
        while pending:
            worktree, repository, oid, prefix = pending.pop()
            source = self.f.repos[repository]
            expected = native_tree(source, oid)
            self.assertEqual(native_tree(worktree, 'HEAD'), expected)
            self.assertEqual(native(worktree, 'cat-file', 'commit', 'HEAD'), native(source, 'cat-file', 'commit', oid))
            seed = {'main':self.selected_tip, 'child':self.child, 'leaf':self.leaf}[repository]
            self.assertEqual(native(worktree, 'for-each-ref', '--format=%(refname) %(objectname)').splitlines(),
                             [f'refs/historycrate/commits/{seed} {seed}'.encode()])
            expected_objects = set(native(source, 'rev-list', '--objects', '--no-object-names', seed).splitlines())
            actual_objects = {line.split()[0] for line in native(worktree, 'cat-file', '--batch-all-objects', '--batch-check').splitlines()}
            self.assertEqual(actual_objects, expected_objects)
            self.assertEqual((worktree/'.git/HEAD').read_text(), oid+'\n')
            self.assertEqual(native(worktree, 'rev-parse', '--verify', 'HEAD'), (oid+'\n').encode())
            self.assertEqual(native(worktree, 'fsck', '--full', '--strict', '--no-reflogs', '--no-dangling'), b'')
            index = {}
            for raw in native(worktree, 'ls-files', '--stage', '-v', '-z').split(b'\0'):
                if raw:
                    header, name = raw.split(b'\t', 1)
                    flag, mode, blob, stage = header.split()
                    self.assertEqual((flag, stage), (b'H', b'0'))
                    index[name.decode()] = (int(mode, 8), blob.decode())
            self.assertEqual(index, {name: (mode, blob) for name, (mode, _, blob) in expected.items()})
            config = (worktree/'.git/config').read_text()
            self.assertIn('/dev/null', config)
            self.assertIn('filter-process --skip', config)
            self.assertIn(str(self.tools.git_lfs), config)
            if staging_path is not None:
                self.assertNotIn(str(staging_path), config)
            self.assertEqual(native(worktree, 'remote'), b'')
            expected_paths = set(expected)
            for name in expected:
                parts = name.split('/')
                expected_paths.update('/'.join(parts[:i]) for i in range(1, len(parts)))
            actual_paths = set()
            def visit(directory, relative=''):
                for path in directory.iterdir():
                    if not relative and path.name == '.git':
                        continue
                    name = relative+path.name
                    actual_paths.add(name)
                    if path.is_dir() and expected.get(name, (None,))[0] != 0o160000:
                        visit(path, name+'/')
            visit(worktree)
            self.assertEqual(actual_paths, expected_paths)
            for name, (mode, kind, blob) in expected.items():
                target = worktree/name
                if mode == 0o160000:
                    full = prefix+name
                    expected_links[full] = blob
                    self.assertTrue((target/'.git').is_dir())
                    pending.append((target, self.routes[repository, name], blob, full+'/'))
                    continue
                self.assertTrue(target.is_file())
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), mode & 0o777)
                self.assertEqual(native(worktree, 'hash-object', '--path='+name, '--', name), (blob+'\n').encode())
                original = native(source, 'cat-file', 'blob', blob)
                if name == "dir/space apostrophe'.bin":
                    expected_bytes = self.payload
                    cached = worktree/'.git/lfs/objects'/self.digest[:2]/self.digest[2:4]/self.digest
                    self.assertEqual(cached.read_bytes(), self.payload)
                    self.assertEqual(cached.stat().st_nlink, 1)
                    self.assertNotEqual(cached.stat().st_ino, target.stat().st_ino)
                elif name.endswith('.txt'):
                    expected_bytes = original.replace(b'\n', b'\r\n')
                else:
                    expected_bytes = original
                self.assertEqual(target.read_bytes(), expected_bytes)
            for args in (('diff', '--cached', '--no-ext-diff', '--no-textconv', '--ignore-submodules=none', '--exit-code'),
                         ('diff', '--no-ext-diff', '--no-textconv', '--ignore-submodules=none', '--exit-code'),
                         ('status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignore-submodules=none')):
                self.assertEqual(native(worktree, *args), b'')
        lines = native(output, '-c', 'core.quotePath=false', 'submodule', 'status', '--recursive').splitlines()
        actual_links = {}
        for line in lines:
            self.assertEqual(line[:1], b' ')
            oid, path = line[1:41].decode(), line[42:].decode()
            if ' (' in path:
                path = path.rsplit(' (', 1)[0]
            actual_links[path] = oid
        self.assertEqual(actual_links, expected_links)

    def test_independent_native_all_revisions_and_source_integrity(self):
        before = {repo: inventory(path) for repo, path in self.f.repos.items()}
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            verified = verify_packet(packet, job)
            for commit in (self.first, self.absent, self.tip):
                output = self.root/commit
                result = restore_verified(verified, 'release', commit, output, job)
                self.assertEqual(result.commit, commit)
                self.assert_native_restore(output, commit, job.root)
        self.assertEqual(before, {repo: inventory(path) for repo, path in self.f.repos.items()})

    def test_postpublication_global_filter_and_poisoned_path_from_nested_directory(self):
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            verified = verify_packet(packet, job)
            output = self.root/'output'
            restore_verified(verified, 'release', self.tip, output, job)
        global_config = self.root/'ordinary-global'
        global_config.write_text('[filter "lfs"]\n process = git-lfs filter-process\n required = true\n')
        poison = self.root/'poison'
        poison.mkdir()
        marker = self.root/'unexpected-helper'
        for name in ('git', 'git-lfs'):
            helper = poison/name
            helper.write_text('#!/bin/sh\nprintf bad > '+str(marker)+'\nexit 97\n')
            helper.chmod(0o755)
        env = {'PATH':str(poison)+':/usr/bin:/bin', 'HOME':str(self.root), 'GIT_CONFIG_GLOBAL':str(global_config),
               'GIT_CONFIG_NOSYSTEM':'1', 'LC_ALL':'C'}
        for child in ('new', 'shared'):
            cwd = output/child/'dir'
            for args in (('status', '--porcelain=v1', '-z', '--untracked-files=all'),
                         ('diff', '--no-ext-diff', '--no-textconv', '--exit-code'),
                         ('hash-object', "--path=space apostrophe'.bin", '--', "space apostrophe'.bin")):
                result = subprocess.run([str(self.tools.git), *args], cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 0, result.stderr)
                if args[0] == 'hash-object':
                    expected = native_tree(self.f.repos['child'], self.child)["dir/space apostrophe'.bin"][2]
                    self.assertEqual(result.stdout, (expected+'\n').encode())
                else:
                    self.assertEqual(result.stdout, b'')
        self.assertFalse(marker.exists())

    def test_materializer_cannot_hide_index_flags_extra_paths_or_payload_changes(self):
        from historycrate import restore as implementation
        real_check = implementation.check_restored_tree
        def changed(root, kind):
            if kind in ('--assume-unchanged', '--skip-worktree'):
                native(root, 'update-index', kind, '--', 'plain')
            elif kind == 'extra-ignored':
                (root/'.git/info').mkdir(exist_ok=True)
                (root/'.git/info/exclude').write_text('hidden\n')
                (root/'hidden').write_bytes(b'hidden')
            elif kind == 'empty-directory':
                (root/'extra-empty').mkdir()
            elif kind == 'lfs-cache':
                (root/'new/.git/lfs/objects'/self.digest[:2]/self.digest[2:4]/self.digest).write_bytes(b'changed')
            elif kind == 'ordinary':
                path = root/'plain'; previous = path.stat()
                path.write_bytes(b'wrong\n')
                os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            verified = verify_packet(packet, job)
            for number, kind in enumerate(('--assume-unchanged', '--skip-worktree', 'extra-ignored', 'empty-directory', 'lfs-cache', 'ordinary')):
                with self.subTest(kind=kind):
                    output = self.root/('rejected-'+str(number))
                    def corrupt_then_check(root, *args):
                        changed(root, kind)
                        return real_check(root, *args)
                    with mock.patch.object(implementation, 'check_restored_tree', side_effect=corrupt_then_check):
                        with self.assertRaises(CrateError) as caught:
                            restore_verified(verified, 'release', self.tip, output, job)
                    if kind == 'ordinary':
                        self.assertEqual(caught.exception.context.get('check'), 'clean-hash')
                    self.assertFalse(output.exists())

    def test_late_source_packet_and_snapshot_changes_block_restore_publication(self):
        from historycrate import publication
        for kind in ('source', 'packet', 'snapshot'):
            with self.subTest(kind=kind), self.job() as job:
                packet, _ = build_packet(self.spec, job)
                verified = verify_packet(packet, job)
                target = {'source':self.f.repos['main']/'config', 'packet':packet/'repos/main.bundle',
                          'snapshot':verified.private_root/'packet/repos/main.bundle'}[kind]
                original = target.read_bytes()
                real_copy = publication._copy
                def mutate_after_copy(*args, **kwargs):
                    real_copy(*args, **kwargs)
                    target.write_bytes(original+b'changed')
                output = self.root/('late-'+kind)
                try:
                    with mock.patch.object(publication, '_copy', side_effect=mutate_after_copy):
                        with self.assertRaises(CrateError) as caught:
                            restore_verified(verified, 'release', self.tip, output, job)
                    self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
                    self.assertEqual(caught.exception.context.get('publication'), 'not-published')
                    self.assertFalse(output.exists())
                    self.assertFalse(any(p.name.startswith('.historycrate-publish-') for p in self.root.iterdir()))
                finally:
                    target.write_bytes(original)

    def test_restore_postcommit_result_failure_keeps_publication_status(self):
        from historycrate import restore as implementation
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            verified = verify_packet(packet, job)
            output = self.root/'committed'
            with mock.patch.object(implementation, 'RestoreResult', side_effect=RuntimeError('injected result failure')):
                with self.assertRaises(CrateError) as caught:
                    restore_verified(verified, 'release', self.absent, output, job)
            self.assertEqual(caught.exception.exit_code, 6)
            self.assertEqual(caught.exception.context.get('publication'), 'published-durability-uncertain')
            self.assert_native_restore(output, self.absent)

    def test_cancellation_after_publication_return_keeps_commit_status(self):
        import sys
        from historycrate import restore as implementation
        previous_trace = sys.gettrace()
        triggered = []
        wrapper = interrupt_after_return(implementation.publish_tree, implementation.restore_verified, triggered)
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            verified = verify_packet(packet, job)
            output = self.root/'committed-cancellation'
            caught = None
            try:
                with mock.patch.object(implementation, 'publish_tree', side_effect=wrapper):
                    try: restore_verified(verified, 'release', self.absent, output, job)
                    except BaseException as exc: caught = exc
            finally:
                sys.settrace(previous_trace)
            self.assertEqual(len(triggered), 1)
            self.assertIsInstance(caught, CrateError)
            self.assertEqual(caught.exit_code, 6)
            self.assertEqual(caught.context.get('publication'), 'published-durability-uncertain')
            self.assert_native_restore(output, self.absent)

    def test_cancellation_during_restore_final_cleanup_keeps_commit_status(self):
        import sys
        from historycrate import restore as implementation
        previous_trace = sys.gettrace()
        triggered = []
        wrapper = interrupt_after_return(implementation.RestoreResult, implementation.restore_verified, triggered)
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            verified = verify_packet(packet, job)
            output = self.root/'cleanup-cancellation'
            caught = None
            try:
                with mock.patch.object(implementation, 'RestoreResult', side_effect=wrapper):
                    try: restore_verified(verified, 'release', self.absent, output, job)
                    except BaseException as exc: caught = exc
            finally:
                sys.settrace(previous_trace)
            self.assertEqual(len(triggered), 1)
            self.assertIsInstance(caught, CrateError)
            self.assertEqual(caught.exit_code, 6)
            self.assertEqual(caught.context.get('publication'), 'published-durability-uncertain')
            self.assert_native_restore(output, self.absent)

    def test_cancellation_after_atomic_return_preserves_readonly_committed_copy(self):
        import sys
        from historycrate import publication
        previous_trace = sys.gettrace()
        triggered = []
        wrapper = interrupt_after_return(publication.paths.atomic_publish, publication.publish_tree, triggered)
        with self.job() as job:
            source = job.root/'review-publication-tree'
            source.mkdir()
            directory = source/'readonly'
            directory.mkdir()
            (directory/'bytes').write_bytes(b'original committed bytes')
            directory.chmod(0o555)
            output = self.root/'atomic-return'
            caught = None
            try:
                with mock.patch.object(publication.paths, 'atomic_publish', side_effect=wrapper):
                    try: publication.publish_tree(source, output, job, job.limits.restore_bytes)
                    except BaseException as exc: caught = exc
            finally:
                sys.settrace(previous_trace)
                directory.chmod(0o700)
            self.assertEqual(len(triggered), 1)
            self.assertIsInstance(caught, CrateError)
            self.assertEqual(caught.exit_code, 6)
            self.assertEqual(caught.context.get('publication'), 'published-durability-uncertain')
            self.assertEqual((output/'readonly/bytes').read_bytes(), b'original committed bytes')
            self.assertEqual(stat.S_IMODE((output/'readonly').stat().st_mode), 0o555)
            self.assertFalse(any(p.name.startswith('.historycrate-publish-') for p in self.root.iterdir()))

    def test_cancellation_during_publication_final_cleanup_keeps_commit_status(self):
        import sys
        from historycrate import publication
        previous_trace = sys.gettrace()
        triggered = []
        wrapper = interrupt_after_return(publication.PublicationReport, publication.publish_tree, triggered)
        with self.job() as job:
            source = job.root/'review-publication-cleanup'
            source.mkdir()
            (source/'bytes').write_bytes(b'clean committed bytes')
            output = self.root/'publication-cleanup'
            caught = None
            try:
                with mock.patch.object(publication, 'PublicationReport', side_effect=wrapper):
                    try: publication.publish_tree(source, output, job, job.limits.restore_bytes)
                    except BaseException as exc: caught = exc
            finally:
                sys.settrace(previous_trace)
            self.assertEqual(len(triggered), 1)
            self.assertIsInstance(caught, CrateError)
            self.assertEqual(caught.exit_code, 6)
            self.assertEqual(caught.context.get('publication'), 'published-durability-uncertain')
            self.assertEqual((output/'bytes').read_bytes(), b'clean committed bytes')
            self.assertFalse(job.native.busy)
            self.assertEqual(job.external_materialized_bytes, 0)

    def test_cancellation_after_packet_publication_return_keeps_commit_status(self):
        import sys
        from historycrate import publication, packet as implementation
        previous_trace = sys.gettrace()
        triggered = []
        wrapper = interrupt_after_return(publication.publish_tree, implementation.create_packet, triggered)
        with self.job() as job:
            output = self.root/'packet-return'
            caught = None
            try:
                with mock.patch.object(publication, 'publish_tree', side_effect=wrapper):
                    try: implementation.create_packet(self.spec, output, job)
                    except BaseException as exc: caught = exc
            finally:
                sys.settrace(previous_trace)
            self.assertEqual(len(triggered), 1)
            self.assertIsInstance(caught, CrateError)
            self.assertEqual(caught.exit_code, 6)
            self.assertEqual(caught.context.get('publication'), 'published-durability-uncertain')
            with self.job() as checker:
                verified = verify_packet(output, checker)
                self.assertEqual(set(verified.closure.root_ancestors['release']), {self.first, self.absent, self.tip})

    def test_successful_prior_publication_cannot_contaminate_precommit_failures(self):
        from historycrate import publication
        with self.job() as job:
            source = job.root/'review-repeated-publication'
            source.mkdir()
            (source/'bytes').write_bytes(b'one')
            first, second = self.root/'first-output', self.root/'second-output'
            publication.publish_tree(source, first, job, job.limits.restore_bytes)
            with mock.patch.object(publication, '_copy', side_effect=CrateError('REVIEW_PRECOMMIT_FAILURE', 4)):
                with self.assertRaises(CrateError) as caught:
                    publication.publish_tree(source, second, job, job.limits.restore_bytes)
            self.assertEqual(caught.exception.context.get('publication'), 'not-published')
            self.assertFalse(second.exists())
            with self.assertRaises(CrateError) as caught:
                publication.publish_tree(source, first, job, job.limits.restore_bytes)
            self.assertEqual(caught.exception.context.get('publication'), 'not-published')
            self.assertEqual(caught.exception.code, 'DESTINATION_EXISTS')
            self.assertEqual((first/'bytes').read_bytes(), b'one')

    def test_parenthesized_submodule_paths_do_not_confuse_native_status(self):
        files = {'.gitmodules': modules(('plain', 'dep', '../child'), ('parens', 'dep (other)', '../child')),
                 'dep': (0o160000, self.child), 'dep (other)': (0o160000, self.child)}
        tip = self.f.commit('main', files)
        self.selected_tip = tip
        self.routes.update({('main', 'dep'):'child', ('main', 'dep (other)'):'child'})
        spec = self.f.spec([('release', 'main', (tip,))], [('main', 'dep', '../child', 'child'),
                           ('main', 'dep (other)', '../child', 'child'), ('child', 'nested', '../leaf', 'leaf')])
        with self.job() as job:
            packet, _ = build_packet(spec, job)
            verified = verify_packet(packet, job)
            output = self.root/'parentheses'
            restore_verified(verified, 'release', tip, output, job)
            self.assert_native_restore(output, tip)


class ReviewCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(GIT, LFS, Limits())

    def setUp(self):
        from historycrate.acquire import acquire_repository
        from historycrate.model import RepoSpec
        from historycrate.objects import ObjectReader
        from tests.fixtures.git_stores import store, history
        self.tmp = tempfile.TemporaryDirectory(prefix='historycrate-independent-cache-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = store(self.root/'source')
        self.commit, self.tree, self.blob = history(self.source)
        self.job = Job(Limits(), self.tools, output_parent=self.root)
        self.job.__enter__()
        self.addCleanup(self.job.__exit__, None, None, None)
        self.acquired = acquire_repository(RepoSpec('main', self.source, self.source/'lfs/objects'), self.job)
        self.reader = ObjectReader(self.acquired, self.job)

    def test_immutable_lru_values_account_for_every_reader_and_budget(self):
        from historycrate.objects import ObjectReader
        from tests.fixtures.git_stores import loose
        self.job.limits = self.job.limits.lower({'commits':2})
        commit = self.reader.commit(self.commit)
        tree = self.reader.tree(self.tree)
        with self.assertRaises(FrozenInstanceError): commit.tree = '0'*40
        with self.assertRaises(FrozenInstanceError): tree[0].oid = '0'*40
        second = ObjectReader(self.acquired, self.job)
        self.assertIs(second.commit(self.commit), commit)
        self.assertIs(second.tree(self.tree), tree)
        self.assertEqual(set(second.records), {self.commit, self.tree})
        self.reader.commit(self.commit)
        extra = loose(self.acquired.stage_git_dir, 'tree', b'')
        self.reader.tree(extra)
        cache = self.job._parsed_object_cache
        self.assertEqual(len(cache.entries), 2)
        self.assertTrue(any(key[1] == self.commit for key in cache.entries))
        self.assertFalse(any(key[1] == self.tree for key in cache.entries))
        self.assertLessEqual(cache.used_bytes, min(self.job.limits.captured_bytes, self.job.limits.observed_rss_bytes//16))
        self.job.budget = Budget(Limits().lower({'git_objects':1}))
        self.reader.commit(self.commit)
        with self.assertRaises(CrateError) as caught: self.reader.tree(extra)
        self.assertEqual(caught.exception.context['resource'], 'git_objects')

    def test_byte_bound_lru_and_lowered_cache_limits(self):
        from tests.fixtures.git_stores import loose, tree_bytes
        self.job.limits = self.job.limits.lower({'captured_bytes':2000})
        first = self.reader.commit(self.commit)
        self.reader.tree(self.tree)
        cache = self.job._parsed_object_cache
        self.assertLessEqual(cache.used_bytes, 2000)
        self.assertEqual(cache.used_bytes, sum(entry[1] for entry in cache.entries.values()))
        large = loose(self.acquired.stage_git_dir, 'tree', tree_bytes(tuple((0o100644, ('path-%04d'%i).encode(), self.blob) for i in range(25))))
        self.reader.tree(large)
        self.assertFalse(any(key[1] == large for key in cache.entries))
        self.assertLessEqual(cache.used_bytes, 2000)
        self.job.limits = self.job.limits.lower({'commits':0})
        self.reader.commit(self.commit)
        self.assertEqual(cache.used_bytes, 0)
        self.assertEqual(len(cache.entries), 0)

    def test_cache_hit_rejects_replaced_staging_and_late_source_mutation(self):
        from historycrate.acquire import recheck_sources
        self.reader.commit(self.commit)
        (self.source/'config').write_text((self.source/'config').read_text()+'\n# source changed\n')
        with self.assertRaises(CrateError) as caught: recheck_sources(self.job)
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
        path = self.acquired.stage_git_dir
        moved = path.with_name(path.name+'-moved')
        path.rename(moved)
        path.mkdir()
        try:
            with self.assertRaises(CrateError) as caught: self.reader.commit(self.commit)
            self.assertEqual(caught.exception.code, 'STAGING_CHANGED')
        finally:
            path.rmdir(); moved.rename(path)

    def test_cached_gitmodules_still_enforces_lowered_native_config_bound(self):
        from historycrate.metadata import read_gitmodules
        from tests.fixtures.git_stores import loose, tree_bytes, commit_bytes
        raw = b'[submodule "old"]\npath = gone\nurl = ../old\n'
        blob = loose(self.acquired.stage_git_dir, 'blob', raw)
        tree = loose(self.acquired.stage_git_dir, 'tree', tree_bytes(((0o100644, b'.gitmodules', blob),)))
        tip = loose(self.acquired.stage_git_dir, 'commit', commit_bytes(tree))
        self.assertEqual(read_gitmodules(self.reader, tip), {'gone': ('old', '../old')})
        self.job.limits = self.job.limits.lower({'config_bytes':1})
        with self.assertRaises(CrateError) as caught:
            read_gitmodules(self.reader, tip)
        self.assertEqual(caught.exception.context.get('resource'), 'config_bytes')

    def test_cached_tree_still_charges_path_visits_and_native_reads_for_blobs(self):
        from historycrate.metadata import walk_tree
        self.assertEqual(set(walk_tree(self.reader, self.commit, self.job)), {'file'})
        self.job.budget = Budget(Limits().lower({'commit_path_visits':0}))
        with self.assertRaises(CrateError) as caught:
            walk_tree(self.reader, self.commit, self.job)
        self.assertEqual(caught.exception.context.get('resource'), 'commit_path_visits')
        before = len(self.job.native.records)
        self.assertEqual(self.reader.read(self.blob), ('blob', b'hello\n'))
        output = io.BytesIO()
        self.reader.copy_blob(self.blob, output)
        self.assertEqual(output.getvalue(), b'hello\n')
        self.assertEqual(len(self.job.native.records)-before, 2)

    def test_cached_gitmodules_copy_does_not_hide_objects_from_new_reader(self):
        from historycrate.metadata import read_gitmodules
        from historycrate.objects import ObjectReader
        from tests.fixtures.git_stores import loose, tree_bytes, commit_bytes
        raw = b'[submodule "old"]\npath = gone\nurl = ../old\n'
        blob = loose(self.acquired.stage_git_dir, 'blob', raw)
        tree = loose(self.acquired.stage_git_dir, 'tree', tree_bytes(((0o100644, b'.gitmodules', blob),)))
        tip = loose(self.acquired.stage_git_dir, 'commit', commit_bytes(tree))
        first = read_gitmodules(self.reader, tip)
        first['gone'] = ('poisoned', '../different')
        before = len(self.job.native.records)
        reader = ObjectReader(self.acquired, self.job)
        self.assertEqual(read_gitmodules(reader, tip), {'gone': ('old', '../old')})
        self.assertEqual(set(reader.records), {tip, tree, blob})
        self.assertEqual(len(self.job.native.records), before)

    def test_fresh_packet_verifier_does_not_reuse_poisoned_parent_parsed_cache(self):
        f = HistoryBuilder(self.root/'fixture')
        f.root.mkdir()
        f.repository('root')
        tip = f.commit('root', {'file':b'original\n'})
        spec = f.spec([('release', 'root', (tip,))])
        with Job(spec.limits, self.tools) as job:
            packet, _ = build_packet(spec, job)
            cache = job._parsed_object_cache
            before = len(job.native.records)
            with mock.patch.object(cache, 'get', side_effect=AssertionError('builder cache reused')):
                verified = verify_packet(packet, job)
            self.assertEqual(set(verified.closure.root_ancestors['release']), {tip})
            commands = job.native.records[before:]
            self.assertTrue(any('cat-file' in entry['argv'] for entry in commands))
            self.assertTrue(any('--filters' in entry['argv'] for entry in commands))


if __name__ == '__main__':
    unittest.main()
