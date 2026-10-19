from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.model import RepoSpec
from historycrate.native import Job, qualify_toolchain
from tests.fixtures.git_stores import store, history, canonical, loose, tree_bytes, commit_bytes

ROOT = Path(__file__).resolve().parents[1]


class ObjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(TEST_GIT, TEST_LFS, Limits())

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.objects'), 'canonical object reader is not implemented')
        from historycrate import objects
        self.o = objects
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = store(self.base / 'source')
        self.commit_oid, self.tree_oid, self.blob_oid = history(self.source)
        self.job = Job(Limits(), self.tools, output_parent=self.base)
        self.job.__enter__()
        self.addCleanup(self.job.__exit__, None, None, None)
        from historycrate.acquire import acquire_repository
        self.acquired = acquire_repository(RepoSpec('source', self.source, self.source / 'lfs/objects'), self.job)
        self.reader = objects.ObjectReader(self.acquired, self.job)

    def test_read_commit_tree_and_stream_blob(self):
        self.assertEqual(self.reader.read(self.blob_oid), ('blob', b'hello\n'))
        commit = self.reader.commit(self.commit_oid)
        self.assertEqual((commit.repository, commit.tree, commit.parents), ('source', self.tree_oid, ()))
        entries = self.reader.tree(self.tree_oid)
        self.assertEqual([(e.mode, e.name, e.oid) for e in entries], [(0o100644, b'file', self.blob_oid)])
        output = io.BytesIO()
        record = self.reader.copy_blob(self.blob_oid, output)
        self.assertEqual(output.getvalue(), b'hello\n')
        self.assertEqual((record.repository, record.kind, record.size), ('source', 'blob', 6))
        self.assertEqual(self.reader.info(self.blob_oid), record)
        self.assertEqual(set(self.reader.records), {self.commit_oid, self.tree_oid, self.blob_oid})

    def test_missing_and_wrong_type_errors_are_precise(self):
        for method, code in ((self.reader.read, 'MISSING_OBJECT'), (self.reader.commit, 'MISSING_COMMIT'),
                             (self.reader.tree, 'MISSING_TREE'), (lambda oid: self.reader.copy_blob(oid, io.BytesIO()), 'MISSING_BLOB')):
            with self.subTest(code=code), self.assertRaises(CrateError) as caught: method('a' * 40)
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(caught.exception.context['oid'], 'a' * 40)
        with self.assertRaises(CrateError) as caught: self.reader.commit(self.blob_oid)
        self.assertEqual(caught.exception.code, 'OBJECT_TYPE_MISMATCH')
        with self.assertRaises(CrateError): self.reader.copy_blob(self.tree_oid, io.BytesIO())

    def test_oid_expressions_never_reach_native(self):
        before = len(self.job.native.records)
        for oid in ('HEAD', self.blob_oid.upper(), self.blob_oid + '^{commit}', 'a' * 39):
            with self.subTest(oid=oid), self.assertRaises(CrateError): self.reader.read(oid)
        self.assertEqual(len(self.job.native.records), before)

    def test_object_hash_and_size_mismatch(self):
        from historycrate.native import _ObjectFrame
        good = canonical('blob', b'abc')[0]
        cases = ((good.encode() + b' blob 3\nxyz\n', 'OBJECT_HASH_MISMATCH'),
                 (good.encode() + b' blob 4\nabc\n', 'TRUNCATED_OBJECT_FRAME'),
                 (good.encode() + b' blob 03\nabc\n', 'INVALID_OBJECT_FRAME'))
        for data, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(CrateError) as caught:
                    frame = _ObjectFrame(io.BytesIO(), good, 100, verify=True)
                    frame.write(data)
                    frame.finish()
                self.assertEqual(caught.exception.code, code)

    def test_object_size_limit_at_exact_boundary(self):
        from historycrate.native import _ObjectFrame
        oid = canonical('blob', b'abc')[0]
        frame = _ObjectFrame(io.BytesIO(), oid, 3, verify=True)
        frame.write(f'{oid} blob 3\n'.encode() + b'abc\n')
        frame.finish()
        self.assertEqual((frame.kind, frame.size), ('blob', 3))
        with self.assertRaises(CrateError) as caught:
            _ObjectFrame(io.BytesIO(), oid, 2, verify=True).write(f'{oid} blob 3\n'.encode())
        self.assertEqual(caught.exception.exit_code, 5)

    def test_commit_parser_preserves_parent_order_and_embedded_signature(self):
        tree = self.tree_oid
        parents = ('1' * 40, '2' * 40)
        data = commit_bytes(tree, parents).replace(b'\n\n', b'\ngpgsig signed\n continuation\n\n', 1)
        record = self.o.parse_commit('source', canonical('commit', data)[0], data)
        self.assertEqual(record.parents, parents)
        self.assertEqual(record.tree, tree)
        for malformed in (b'tree xyz\n\n', b'tree ' + tree.encode() + b'\ntree ' + tree.encode() + b'\n\n',
                          b'parent ' + parents[0].encode() + b'\ntree ' + tree.encode() + b'\n\n'):
            with self.subTest(malformed=malformed), self.assertRaises(CrateError):
                self.o.parse_commit('source', canonical('commit', malformed)[0], malformed)

    def test_tree_parser_preserves_byte_names_and_rejects_truncation_duplicates_order(self):
        data = tree_bytes(((0o100644, b'-leading', self.blob_oid), (0o100644, b':wq', self.blob_oid),
                           (0o100644, b'apostrophe\'file', self.blob_oid)))
        entries = self.o.parse_tree(data)
        self.assertEqual([e.name for e in entries], [b'-leading', b':wq', b"apostrophe'file"])
        for malformed in (data[:-1], b'100644 missing-nul', tree_bytes(((0o100644, b'x', self.blob_oid), (0o100644, b'x', self.blob_oid))),
                          tree_bytes(((0o100644, b'z', self.blob_oid), (0o100644, b'a', self.blob_oid)))):
            with self.subTest(malformed=malformed), self.assertRaises(CrateError): self.o.parse_tree(malformed)

    def test_unique_object_count_is_enforced_and_repeated_reads_are_free(self):
        self.reader.info(self.blob_oid)
        self.reader.read(self.blob_oid)
        self.reader.copy_blob(self.blob_oid, io.BytesIO())
        self.assertEqual(self.job.budget.used['git_objects'], 1)
        from historycrate.limits import Budget
        self.job.budget = Budget(Limits().lower({'git_objects': 1}))
        self.reader = self.o.ObjectReader(self.acquired, self.job)
        self.reader.info(self.blob_oid)
        before = len(self.job.native.records)
        with self.assertRaises(CrateError) as caught: self.reader.tree(self.tree_oid)
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(len(self.job.native.records), before)

    def test_info_reuses_verified_metadata_without_retaining_payload(self):
        record = self.reader.info(self.blob_oid)
        before = len(self.job.native.records)
        self.assertIs(self.reader.info(self.blob_oid), record)
        self.assertEqual(len(self.job.native.records), before)

    def test_tree_parser_stops_at_lowered_entry_budget(self):
        import inspect
        self.assertIn('maximum_entries', inspect.signature(self.o.parse_tree).parameters, 'tree entry admission is missing')
        data = tree_bytes(((0o100644, b'a', self.blob_oid), (0o100644, b'b', self.blob_oid)))
        with self.assertRaises(CrateError) as caught:
            self.o.parse_tree(data, maximum_entries=1)
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(caught.exception.context['resource'], 'commit_path_visits')
        self.assertEqual(len(self.o.parse_tree(data, maximum_entries=2)), 2)
        self.assertEqual(self.o.parse_tree(b'', maximum_entries=0), ())
        self.job.limits = self.job.limits.lower({'commit_path_visits': 0})
        with self.assertRaises(CrateError) as caught: self.reader.tree(self.tree_oid)
        self.assertEqual(caught.exception.exit_code, 5)

    def test_tree_parser_calls_checkpoint_in_bounded_chunks(self):
        import inspect
        self.assertIn('checkpoint', inspect.signature(self.o.parse_tree).parameters, 'tree parser checkpoints are missing')
        data = tree_bytes(tuple((0o100644, f'file-{i:04d}'.encode(), self.blob_oid) for i in range(2050)))
        calls = []
        def checkpoint():
            calls.append(True)
            if len(calls) == 2:
                raise CrateError('AUTHORED_CHECKPOINT_ABORT', 5)
        with self.assertRaises(CrateError) as caught:
            self.o.parse_tree(data, maximum_entries=2050, checkpoint=checkpoint)
        self.assertEqual(caught.exception.code, 'AUTHORED_CHECKPOINT_ABORT')
        self.assertEqual(len(calls), 2)
        calls.clear()
        self.assertEqual(len(self.o.parse_tree(data, checkpoint=lambda: calls.append(True))), 2050)
        self.assertEqual(len(calls), 3)
