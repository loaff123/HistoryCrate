from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
"""Independent review regressions for the bounded Task 3–5 implementation.

All inputs are original disposable fixtures. No external repository is read.
"""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from historycrate.acquire import RepositoryPool, acquire_repository
from historycrate.closure import build_closure
from historycrate.errors import CrateError
from historycrate.lfs import collect_payloads, hydrate_file
from historycrate.limits import Limits
from historycrate.model import RepoSpec
from historycrate.native import Job, qualify_toolchain
from tests.fixtures.git_stores import store, history
from tests.fixtures.histories import HistoryBuilder
from tests.fixtures.lfs_cases import pointer, write_cache

ROOT = Path(__file__).resolve().parents[1]


class IndependentStageReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(TEST_GIT, TEST_LFS, Limits())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='historycrate-review-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_pointer_payload_must_roundtrip_through_native_lfs_clean(self):
        f = HistoryBuilder(self.base)
        source = f.repository('main')
        nested = pointer(b'original inner fixture data')
        outer = pointer(nested)
        tip = f.commit('main', {'.gitattributes': b'file filter=lfs -text\n', 'file': outer})
        spec = f.spec([('release', 'main', (tip,))])
        write_cache(source/'lfs/objects', nested)
        with Job(spec.limits, self.tools, source_paths=(source,)) as job:
            closure = build_closure(spec, RepositoryPool(spec, job), job)
            # Independent native proof: clean recognizes the payload as an
            # existing pointer, so it cannot reproduce the stored outer pointer.
            actual = job.native.run('lfs_clean', {'repo': 'main', 'path': 'file'}, nested).stdout
            self.assertEqual(actual, nested)
            self.assertNotEqual(actual, outer)
            with self.assertRaises(CrateError):
                collect_payloads(closure, spec.repositories, job)

    def test_source_lfs_extension_and_custom_transfer_are_refused(self):
        variants = {'extension': '[lfs "extension.fixture"]\n clean = /bin/false\n',
                    'custom-transfer': '[lfs "customtransfer.fixture"]\n path = /bin/false\n'}
        for variant, extra in variants.items():
            with self.subTest(variant=variant):
                source = store(self.base/variant)
                history(source)
                with (source/'config').open('a') as out:
                    out.write(extra)
                repo = RepoSpec('main', source, source/'lfs/objects')
                with Job(Limits(), self.tools) as job:
                    with self.assertRaises(CrateError):
                        acquire_repository(repo, job)

    def test_acquired_source_is_automatically_protected_from_hydration(self):
        f = HistoryBuilder(self.base)
        source = f.repository('main')
        payload = b'original fixture payload\n'
        tip = f.commit('main', {'.gitattributes': b'file filter=lfs -text\n', 'file': pointer(payload)})
        spec = f.spec([('release', 'main', (tip,))])
        write_cache(source/'lfs/objects', payload)
        sentinel = source/'source-must-not-change'
        sentinel.write_bytes(b'original source bytes')
        # Public staged APIs permit default Job(source_paths=()); acquisition
        # must preserve the no-source-write invariant for later safe writers.
        with Job(spec.limits, self.tools) as job:
            closure = build_closure(spec, RepositoryPool(spec, job), job)
            record = collect_payloads(closure, spec.repositories, job).records[0]
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(CrateError):
                    hydrate_file(fd, sentinel.name, 0o100644, record, job)
            finally:
                os.close(fd)
            self.assertEqual(sentinel.read_bytes(), b'original source bytes')

    def test_bundle_seed_limit_is_per_repository(self):
        f = HistoryBuilder(self.base)
        f.repository('first'); f.repository('second')
        first = f.commit('first', {'file': b'first'})
        second = f.commit('second', {'file': b'second'})
        spec = f.spec([('one', 'first', (first,)), ('two', 'second', (second,))],
                      limits=Limits().lower({'bundle_seed_refs': 1}))
        with Job(spec.limits, self.tools, source_paths=tuple(f.repos.values())) as job:
            closure = build_closure(spec, RepositoryPool(spec, job), job)
            self.assertEqual(closure.seeds, {'first': (first,), 'second': (second,)})

    def test_depth_limit_prevents_acquiring_beyond_supported_nesting(self):
        from tests.fixtures.histories import modules
        f = HistoryBuilder(self.base)
        for name in ('main', 'child', 'leaf'):
            f.repository(name)
        leaf = f.commit('leaf', {'file': b'leaf'})
        child = f.commit('child', {'.gitmodules': modules(('leaf', 'leaf', '../leaf')),
                                   'leaf': (0o160000, leaf)})
        main = f.commit('main', {'.gitmodules': modules(('child', 'child', '../child')),
                                 'child': (0o160000, child)})
        spec = f.spec([('release', 'main', (main,))],
                      [('main', 'child', '../child', 'child'), ('child', 'leaf', '../leaf', 'leaf')],
                      Limits().lower({'repository_depth': 1}))
        with Job(spec.limits, self.tools, source_paths=tuple(f.repos.values())) as job:
            pool = RepositoryPool(spec, job)
            with self.assertRaises(CrateError) as caught:
                build_closure(spec, pool, job)
            self.assertEqual(caught.exception.context.get('resource'), 'repository_depth')
            self.assertNotIn('leaf', pool.acquired)

    def test_checkout_eol_expansion_is_not_an_oversized_git_object(self):
        f = HistoryBuilder(self.base)
        source = f.repository('main')
        tip = f.commit('main', {'.gitattributes': b'file text eol=crlf\n', 'file': b'\n'*400})
        # Every Git object is below 512 bytes; valid checkout conversion produces
        # 800 bytes, which is not a Git object and remains below scratch limits.
        spec = f.spec([('release', 'main', (tip,))], limits=Limits().lower({'git_object_bytes': 512}))
        with Job(spec.limits, self.tools, source_paths=(source,)) as job:
            closure = build_closure(spec, RepositoryPool(spec, job), job)
            self.assertEqual(len(closure.commits), 1)

    def test_direct_payload_collection_guards_source_git_directory(self):
        from historycrate.model import Closure, LfsOccurrence
        source = store(self.base/'source')
        payload = b'original fixture payload\n'
        write_cache(source/'lfs/objects', payload)
        sentinel = source/'source-must-not-change'
        sentinel.write_bytes(b'original source bytes')
        repo = RepoSpec('main', source, source/'lfs/objects')
        occurrence = LfsOccurrence('main', 'a'*40, 'file', 'b'*40,
                                   hashlib.sha256(payload).hexdigest(), len(payload))
        closure = Closure((), {}, {}, (), (), (), (occurrence,))
        with Job(Limits(), self.tools) as job:
            record = collect_payloads(closure, (repo,), job).records[0]
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(CrateError):
                    hydrate_file(fd, sentinel.name, 0o100644, record, job)
            finally:
                os.close(fd)
            self.assertEqual(sentinel.read_bytes(), b'original source bytes')

    def test_small_lfs_clean_probe_obeys_payload_not_git_object_bound(self):
        f = HistoryBuilder(self.base)
        source = f.repository('main')
        payload = b'git-lfs' + b'x'*600
        tip = f.commit('main', {'.gitattributes': b'file filter=lfs -text\n', 'file': pointer(payload)})
        write_cache(source/'lfs/objects', payload)
        spec = f.spec([('release', 'main', (tip,))], limits=Limits().lower({'git_object_bytes': 512}))
        with Job(spec.limits, self.tools, source_paths=(source,)) as job:
            closure = build_closure(spec, RepositoryPool(spec, job), job)
            records = collect_payloads(closure, spec.repositories, job).records
            self.assertEqual(records[0].private_path.read_bytes(), payload)

    def test_incremental_depth_matches_independent_dag_recalculation(self):
        import random
        from historycrate.closure import _GraphGuard
        rng = random.Random(8103)
        for case in range(30):
            vertices = [('same-repository', str(i)) for i in range(25)]
            edges = [(vertices[i], vertices[j]) for i in range(25) for j in range(i+1, 25)
                     if rng.random() < 0.12]
            rng.shuffle(edges)
            guard = _GraphGuard(16, lambda: None)
            accepted = []
            for parent, child in edges:
                accepted.append((parent, child))
                # Independent topological recurrence uses the authored rank,
                # never any production traversal or cached depths.
                expected = {vertex: 0 for vertex in vertices}
                for vertex in vertices:
                    expected[vertex] = max([expected[p] + 1 for p, c in accepted if c == vertex] or [0])
                if max(expected.values()) > 16:
                    with self.assertRaises(CrateError):
                        guard.add(parent, child)
                    break
                guard.add(parent, child)
                self.assertEqual({v: guard.depths.get(v, 0) for v in vertices}, expected, case)

    def _observer_without_rss(self, states, status_error=None):
        import time
        from unittest.mock import patch
        import historycrate.process as process
        fake_pid = 999999
        start = time.monotonic()
        observer = process._Observer(Limits(), start, start+3, None)
        observer.direct_pid = fake_pid
        observer.discovery_method = 'bounded-procfs-ppid-session'
        original_identity = process._identity
        original_read = process._bounded_read
        calls = {'identity': 0, 'status': 0}
        def identity(pid):
            if pid != fake_pid:
                return original_identity(pid)
            index = calls['identity']; calls['identity'] += 1
            value = states[min(index, len(states)-1)]
            return value
        def read(path):
            if path == Path('/proc')/str(fake_pid)/'status':
                calls['status'] += 1
                if status_error is not None:
                    raise status_error
                return b'Name:\tgit\nState:\tR (running)\nThreads:\t1\n'
            return original_read(path)
        with patch.object(observer, '_fallback_snapshot', return_value={}), \
             patch.object(process, '_identity', side_effect=identity), \
             patch.object(process, '_bounded_read', side_effect=read):
            observer.sample()
        return observer, calls

    def test_absent_rss_teardown_window_requires_confirmed_exit(self):
        live = (100, 'R', 999999, 999999)
        exited = (100, 'Z', 999999, 999999)
        observer, calls = self._observer_without_rss([live, live, exited])
        self.assertTrue(observer.known[999999]['exited'])
        self.assertNotIn('999999', observer.samples[-1]['rss_bytes'])
        self.assertGreaterEqual(calls['identity'], 3)

    def test_absent_rss_genuinely_live_process_still_fails_closed(self):
        live = (100, 'R', 999999, 999999)
        with self.assertRaises(CrateError) as caught:
            self._observer_without_rss([live])
        self.assertIn(caught.exception.code, ('OBSERVATION_MALFORMED', 'OBSERVATION_TIME_LIMIT', 'OBSERVATION_ENTRY_LIMIT'))

    def test_absent_rss_permission_denial_is_still_fatal(self):
        live = (100, 'R', 999999, 999999)
        with self.assertRaises(CrateError) as caught:
            self._observer_without_rss([live], PermissionError(13, 'denied'))
        self.assertEqual(caught.exception.code, 'OBSERVATION_UNREADABLE')

    def test_absent_rss_pid_reuse_never_samples_replacement(self):
        original = (100, 'R', 999999, 999999)
        replacement = (101, 'R', 42, 42)
        observer, _ = self._observer_without_rss([original, replacement])
        self.assertTrue(observer.known[999999]['exited'])
        self.assertEqual(observer.known[999999]['starttime'], 100)
        self.assertNotIn('999999', observer.samples[-1]['rss_bytes'])

    def _prepared_conversion(self, job, payload=b'plain\n', attributes=None):
        from historycrate.objects import ObjectReader
        f = HistoryBuilder(self.base)
        source = f.repository('main')
        tip = f.commit('main', {'file': payload})
        spec = f.spec([('release', 'main', (tip,))])
        reader = ObjectReader(RepositoryPool(spec, job).get('main'), job)
        record = reader.commit(tip)
        entry = next(item for item in reader.tree(record.tree) if item.name == b'file')
        reader.info(entry.oid)
        attrs = {'filter': 'unspecified', 'text': 'unspecified', 'eol': 'unspecified',
                 'ident': 'unspecified', 'working-tree-encoding': 'unspecified'}
        attrs.update(attributes or {})
        return reader, tip, entry.oid, attrs

    def test_conversion_reserve_preflight_precedes_native_launch(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from historycrate.metadata import verify_conversion
        with Job(Limits(), self.tools) as job:
            reader, tip, oid, attrs = self._prepared_conversion(job)
            space = SimpleNamespace(f_bavail=63*1024*1024, f_frsize=1)
            with patch('os.fstatvfs', return_value=space), \
                 patch.object(job.native, '_execute', wraps=job.native._execute) as execute:
                with self.assertRaises(CrateError) as caught:
                    verify_conversion(reader, tip, 'file', oid, attrs, job)
            self.assertEqual(caught.exception.code, 'INSUFFICIENT_SPACE')
            self.assertFalse(any('--filters' in call.args[0] for call in execute.call_args_list))
            self.assertFalse((job.root/'artifacts/conversion-payload').exists())

    def test_conversion_preflight_includes_existing_scratch_bytes(self):
        from unittest.mock import patch
        from historycrate.metadata import verify_conversion
        from historycrate.process import _Observer
        import time
        with Job(Limits(), self.tools) as job:
            reader, tip, oid, attrs = self._prepared_conversion(job, b'x'*400)
            now = time.monotonic()
            observer = _Observer(job.limits, now, now+1, job.root)
            observer.sample_scratch()
            current = observer.scratch_samples[-1]['observed_bytes']
            job.limits = job.limits.lower({'scratch_bytes': current+399})
            job.native.limits = job.limits
            with patch.object(job.native, '_execute', wraps=job.native._execute) as execute:
                with self.assertRaises(CrateError) as caught:
                    verify_conversion(reader, tip, 'file', oid, attrs, job)
            self.assertEqual(caught.exception.context['resource'], 'scratch_bytes')
            self.assertFalse(any('--filters' in call.args[0] for call in execute.call_args_list),
                             'conversion started despite known insufficient scratch')
