"""Original miniature fixtures exercise the external acceptance oracle itself."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

from tests.fixtures.histories import HistoryBuilder, modules, native
from tests.toolchain import GIT, LFS, GIT_EXEC


class ChollaOracleTests(unittest.TestCase):
    def load_oracle(self):
        path = Path(__file__).parent / 'external/qualify_cholla.py'
        self.assertTrue(path.is_file(), 'the independent external oracle must exist')
        spec = importlib.util.spec_from_file_location('qualify_cholla', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def setUp(self):
        self.q = self.load_oracle()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = HistoryBuilder(self.root)
        for name in ('main', 'child'):
            self.fixture.repository(name)
        self.payload = b'original qualification payload\0\n'
        self.oid = hashlib.sha256(self.payload).hexdigest()
        pointer = f'version https://git-lfs.github.com/spec/v1\noid sha256:{self.oid}\nsize {len(self.payload)}\n'.encode()
        self.child = self.fixture.commit('child', {'.gitattributes': b'*.bin filter=lfs -text\n', 'data.bin': pointer})
        self.commit = self.fixture.commit('main', {
            '.gitmodules': modules(('data', 'data', '../child')),
            'data': (0o160000, self.child),
            '.gitattributes': b'*.txt text eol=crlf\n',
            'text.txt': b'one\ntwo\n',
            ':wq': b'punctuation',
            'exec': (0o100755, self.fixture.blob('main', b'#!/bin/false\n')),
        })
        self.runner = self.q.NativeOracle(GIT, LFS, GIT_EXEC, self.root/'oracle', self.root/'native.jsonl')
        self.output = self.root/'restore'
        self.runner.copy_object_stage(self.fixture.repos['main'], self.output, bare=False)
        self.runner.git(self.output, 'checkout', '--quiet', '--detach', self.commit)
        self.runner.copy_object_stage(self.fixture.repos['child'], self.output/'data', bare=False)
        self.runner.git(self.output/'data', 'checkout', '--quiet', '--detach', self.child)
        (self.output/'data/data.bin').write_bytes(self.payload)
        self.cache = self.output/'data/.git/lfs/objects'/self.oid[:2]/self.oid[2:4]/self.oid
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        self.cache.write_bytes(self.payload)
        self.runner.git(self.output/'data', 'add', '--', 'data.bin')
        self.runner.git(self.output, 'config', '--local', 'submodule.data.url', 'historycrate-offline:child')
        self.expected = {'root_commit': self.commit, 'submodule_commit': self.child,
                         'verified_lfs_files': [{'path': 'data.bin', 'sha256': self.oid, 'size': len(self.payload)}]}

    def check(self):
        return self.runner.check_restore(self.output, self.expected, child_path='data')

    def test_original_conversion_modes_lfs_and_gitlink_pass(self):
        result = self.check()
        self.assertEqual(result['repositories'], 2)
        self.assertEqual(result['hydrated_files'], 1)
        self.assertEqual((self.output/'text.txt').read_bytes(), b'one\r\ntwo\r\n')

    def test_clean_hash_alone_does_not_hide_wrong_checkout_conversion(self):
        (self.output/'text.txt').write_bytes(b'one\ntwo\n')
        with self.assertRaisesRegex(self.q.QualificationFailure, 'checkout bytes'):
            self.check()

    def test_hidden_index_flags_are_rejected(self):
        self.runner.git(self.output, 'update-index', '--assume-unchanged', '--', ':wq')
        with self.assertRaisesRegex(self.q.QualificationFailure, 'index flags'):
            self.check()

    def test_wrong_lfs_cache_and_mode_are_rejected(self):
        self.cache.write_bytes(b'x'*len(self.payload))
        with self.assertRaisesRegex(self.q.QualificationFailure, 'payload'):
            self.check()
        self.cache.write_bytes(self.payload)
        (self.output/'exec').chmod(0o644)
        with self.assertRaisesRegex(self.q.QualificationFailure, 'mode'):
            self.check()

    def test_absent_child_is_checked_even_when_ignored(self):
        absent = self.fixture.commit('main', {'.gitignore': b'data\n', 'plain': b'original'})
        output = self.root/'absent'
        self.runner.copy_object_stage(self.fixture.repos['main'], output, bare=False)
        self.runner.git(output, 'checkout', '--quiet', '--detach', absent)
        expected = {'root_commit': absent, 'submodule_commit': None, 'verified_lfs_files': []}
        self.runner.check_restore(output, expected, child_path='data')
        (output/'data').mkdir()
        with self.assertRaisesRegex(self.q.QualificationFailure, 'absent child'):
            self.runner.check_restore(output, expected, child_path='data')

    def test_copy_object_stage_does_not_activate_source_config(self):
        marker = self.root/'executed'
        poison = self.fixture.repos['main']/'config'
        poison.write_text('[include]\n path = /not-a-real-config\n[core]\n fsmonitor = touch '+str(marker)+'\n')
        clean = self.root/'clean'
        self.runner.copy_object_stage(self.fixture.repos['main'], clean, bare=True)
        self.assertEqual(self.runner.git(clean, 'cat-file', '-t', self.commit), b'commit\n')
        self.assertFalse(marker.exists())
        self.assertNotIn(b'/not-a-real-config', (clean/'config').read_bytes())

    def test_archive_comparison_is_streamed_and_deterministic(self):
        source = self.root/'small'; source.mkdir()
        (source/'one').write_bytes(b'original fixture\n'*100)
        before = self.q.inventory(source)
        a = self.q.archive_files({'source': source}, self.root/'one.tar.gz')
        b = self.q.archive_files({'source': source}, self.root/'two.tar.gz')
        self.assertEqual(a['regular_file_bytes'], 1700)
        self.assertEqual(a['sha256'], b['sha256'])
        self.assertEqual(before, self.q.inventory(source))

    def test_missing_persistent_filter_is_not_masked_by_oracle_overrides(self):
        self.runner.git(self.output/'data', 'config', '--local', '--unset-all', 'filter.lfs.process')
        with self.assertRaisesRegex(self.q.QualificationFailure, 'missing or wrong persistent config: filter.lfs.process'):
            self.check()

    def test_oracle_accepts_actual_fresh_job_packet_restore(self):
        self.assertTrue(hasattr(self.q, 'check_required_explanations'), 'intact-closure explanation gate must exist')
        self.assertTrue(hasattr(self.q, 'exercise_missing_payload'), 'missing-payload negative gate must exist')
        from historycrate.limits import Limits
        from historycrate.closure import explain_inclusion
        from historycrate.native import Job, qualify_toolchain
        from historycrate.packet import create_packet, verify_packet
        from historycrate.restore import restore_verified
        tools = qualify_toolchain(GIT, LFS, Limits())
        cache = self.fixture.repos['child']/'lfs/objects'/self.oid[:2]/self.oid[2:4]/self.oid
        cache.parent.mkdir(parents=True); cache.write_bytes(self.payload)
        spec = self.fixture.spec([('release', 'main', (self.commit,))], [('main', 'data', '../child', 'child')])
        packet, restored = self.root/'product-packet', self.root/'product-restore'
        with Job(spec.limits, tools, source_paths=tuple(self.fixture.repos.values())) as job:
            create_packet(spec, packet, job)
        with Job(Limits(), tools, source_paths=(packet,)) as job:
            verified = verify_packet(packet, job)
            pointer_blob = native(self.fixture.repos['child'], 'rev-parse', self.child+':data.bin').strip().decode()
            explanations = self.q.check_required_explanations(
                explain_inclusion, verified.closure, repository='child', parent_repository='main',
                parent_commit=self.commit, child_commit=self.child, child_path='data',
                payload={'path': 'data.bin', 'sha256': self.oid, 'size': len(self.payload), 'pointer_blob': pointer_blob})
            self.assertEqual(explanations['requiring_payload']['lfs'][0]['sha256'], self.oid)
            restore_verified(verified, 'release', self.commit, restored, job)
        self.runner.check_restore(restored, self.expected, child_path='data')

        # Keep substantial controller state alive across the negative CLI calls.
        # Their doctor self-check must run in fresh processes, not this controller.
        retained = bytearray(96 * 1024 * 1024)
        for offset in range(0, len(retained), 4096):
            retained[offset] = 1
        negative = self.q.exercise_missing_payload(
            packet, self.root/'damaged-packet', self.root/'blocked-output',
            sha256=self.oid, root_id='release', root_commit=self.commit, git=GIT, git_lfs=LFS)
        self.assertEqual([call['argv'][3] for call in negative['calls']], ['verify', 'restore'])
        self.assertEqual([call['exit_code'] for call in negative['calls']], [4, 4])
        self.assertTrue(negative['intact_packet_unchanged'])
        self.assertFalse((self.root/'blocked-output').exists())

        self.assertEqual(len(retained), 96 * 1024 * 1024)
        for call in negative['calls']:
            self.assertEqual(Path(call['stdout_path']).read_text().strip()[0], '{')
            self.assertTrue(Path(call['stderr_path']).exists())

    def test_failed_subprocess_keeps_exact_output_and_receipt(self):
        result = self.q.run_cli_subprocess(['not-a-command'], self.root/'cli-failure', 'bad')
        self.assertEqual(result['exit_code'], 2)
        self.assertEqual(result['stdout_report']['status'], 'blocked')
        import json
        persisted = json.loads((self.root/'cli-failure/bad.json').read_text())
        self.assertEqual(persisted, result)
        self.assertEqual(self.q.fingerprint(Path(result['stdout_path'])), result['stdout_fingerprint'])
        self.assertEqual(self.q.fingerprint(Path(result['stderr_path'])), result['stderr_fingerprint'])
