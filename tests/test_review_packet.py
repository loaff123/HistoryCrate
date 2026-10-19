"""Independent Task 6 review: authored fixtures and native semantic oracles."""
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job, qualify_toolchain
from historycrate.packet import build_packet, verify_packet
from historycrate.schema import encode_canonical
from tests.fixtures.histories import HistoryBuilder, inventory, native
from tests.oracle.graph import ancestry, objects

ROOT = Path(__file__).resolve().parents[1]

class ReviewPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(TEST_GIT, TEST_LFS, Limits())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='historycrate-review-packet-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.f = HistoryBuilder(self.root)
        self.f.repository('source')
        self.payload = b'x'
        self.digest = hashlib.sha256(self.payload).hexdigest()
        pointer = f'version https://git-lfs.github.com/spec/v1\noid sha256:{self.digest}\nsize 1\n'.encode()
        self.base = self.f.commit('source', {'base': b'base'})
        self.tip = self.f.commit('source', {'.gitattributes': b'*.bin filter=lfs -text\n', 'data.bin': pointer, 'file': b'ordinary'}, (self.base,))
        self.unrelated = self.f.commit('source', {'other': b'excluded'})
        path = self.f.repos['source']/'lfs/objects'/self.digest[:2]/self.digest[2:4]/self.digest
        path.parent.mkdir(parents=True)
        path.write_bytes(self.payload)
        self.spec = self.f.spec([('root', 'source', (self.tip,))])

    def job(self, **kwargs):
        return Job(self.spec.limits, self.tools, **kwargs)

    def rehash(self, packet):
        doc = json.loads((packet/'COMPLETE.json').read_bytes())
        for entry in doc['artifacts']:
            raw = (packet/entry['path']).read_bytes()
            entry['size'] = len(raw)
            entry['sha256'] = hashlib.sha256(raw).hexdigest()
        doc['manifest_sha256'] = hashlib.sha256((packet/'manifest.json').read_bytes()).hexdigest()
        (packet/'COMPLETE.json').write_bytes(encode_canonical(doc))

    def test_complete_artifact_size_boolean_is_not_integer(self):
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            doc = json.loads((packet/'COMPLETE.json').read_bytes())
            entry = next(x for x in doc['artifacts'] if x['path'].startswith('lfs/'))
            self.assertEqual(entry['size'], 1)
            entry['size'] = True
            (packet/'COMPLETE.json').write_bytes(encode_canonical(doc))
            with self.assertRaises(CrateError):
                verify_packet(packet, job)

    def test_malformed_complete_reports_corrupt_input_not_invalid_invocation(self):
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            doc = json.loads((packet/'COMPLETE.json').read_bytes())
            doc['unknown-field'] = 1
            (packet/'COMPLETE.json').write_bytes(encode_canonical(doc))
            with self.assertRaises(CrateError) as caught:
                verify_packet(packet, job)
            self.assertEqual(caught.exception.exit_code, 4)
            self.assertNotEqual(caught.exception.code, 'INVALID_SPEC')

    def test_bundle_trailing_unconsumed_bytes_are_rejected(self):
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            path = packet/'repos/source.bundle'
            with path.open('ab') as stream:
                stream.write(b'UNUSED TRAILER NOT IN A GIT PACK\x00')
            self.rehash(packet)
            with self.assertRaises(CrateError):
                verify_packet(packet, job)

    def test_fresh_job_has_no_original_sources_or_builder_cache(self):
        expected_objects = objects(self.f.repos['source'], (self.tip,))
        expected_commits = ancestry(self.f.repos['source'], (self.tip,))
        before = inventory(self.root)
        with self.job() as builder:
            staged, _ = build_packet(self.spec, builder)
            packet = self.root/'saved'
            shutil.copytree(staged, packet)
        source = self.f.repos['source']
        moved = self.root/'source-unavailable'
        source.rename(moved)
        with self.job() as verifier:
            verifier._conversion_cache = {'poisoned-builder-cache'}
            result = verify_packet(packet, verifier)
            self.assertEqual({c.oid for c in result.closure.commits}, expected_commits)
            self.assertEqual({o.oid for o in result.closure.objects}, expected_objects)
            repo = result.private_root/'imported/repos/source'
            advertised = native(repo, 'for-each-ref', '--format=%(refname) %(objectname)').decode().splitlines()
            self.assertEqual(advertised, [f'refs/historycrate/commits/{self.tip} {self.tip}'])
            self.assertEqual((repo/'HEAD').read_text(), self.tip+'\n')
            self.assertEqual(native(repo, 'fsck', '--full', '--strict', '--no-reflogs', '--no-dangling'), b'')
            conversion_commands = [r for r in verifier.native.records if 'cat-file' in r['argv'] and '--filters' in r['argv']]
            self.assertTrue(conversion_commands, 'fresh verification must perform native conversion checks')
        moved.rename(source)
        shutil.rmtree(packet)
        self.assertEqual(before, inventory(self.root))

    def test_extra_valid_packed_object_cannot_be_declared_into_closure(self):
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            path = packet/'repos/source.bundle'
            header = path.read_bytes().split(b'\n\n', 1)[0]+b'\n\n'
            extra = self.f.blob('source', b'extra otherwise valid native object')
            selected = sorted(objects(self.f.repos['source'], (self.tip,)) | {extra})
            packed = native(self.f.repos['source'], 'pack-objects', '--stdout', data=('\n'.join(selected)+'\n').encode())
            path.write_bytes(header+packed)
            self.rehash(packet)
            with self.assertRaises(CrateError) as caught:
                verify_packet(packet, job)
            self.assertEqual(caught.exception.code, 'PACKET_OBJECT_SET_MISMATCH')
            doc = json.loads((packet/'manifest.json').read_bytes())
            doc['objects'].append({'repository':'source','oid':extra,'kind':'blob','size':len(b'extra otherwise valid native object')})
            doc['objects'].sort(key=lambda x:(x['repository'],x['oid']))
            doc['counts']['objects'] += 1
            (packet/'manifest.json').write_bytes(encode_canonical(doc))
            self.rehash(packet)
            with self.assertRaises(CrateError) as caught:
                verify_packet(packet, job)
            self.assertEqual(caught.exception.code, 'PACKET_SEMANTIC_MISMATCH')

    def test_payload_corruption_is_rejected_even_with_rehashed_complete(self):
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            payload = packet/'lfs/objects'/self.digest[:2]/self.digest[2:4]/self.digest
            payload.write_bytes(b'y')
            self.rehash(packet)
            with self.assertRaises(CrateError) as caught:
                verify_packet(packet, job)
            self.assertEqual(caught.exception.code, 'LFS_HASH_MISMATCH')

    def test_verification_phase_observations_reach_owning_job(self):
        from historycrate.packet import _phase
        from historycrate.monitor import CopyMonitor
        with self.job() as job:
            phase = _phase(job, job.root/'phase')
            monitor = CopyMonitor(phase)
            monitor.check()
            self.assertIn(monitor.report, getattr(job, 'controller_observations', ()))

    def test_late_source_and_payload_mutation_during_publication_block_commit(self):
        from historycrate import publication
        from historycrate.packet import create_packet
        config = self.f.repos['source']/'config'
        payload = self.f.repos['source']/'lfs/objects'/self.digest[:2]/self.digest[2:4]/self.digest
        for target in (config, payload):
            with self.subTest(target=target.name):
                original = target.read_bytes()
                output = self.root/'output'
                copy = publication._copy
                def mutate_after_sibling_copy(*args, **kwargs):
                    copy(*args, **kwargs)
                    target.write_bytes(original+b'changed')
                try:
                    with self.job() as job, mock.patch.object(publication, '_copy', side_effect=mutate_after_sibling_copy):
                        with self.assertRaises(CrateError) as caught:
                            create_packet(self.spec, output, job)
                    self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
                    self.assertEqual(caught.exception.context.get('publication'), 'not-published')
                    self.assertFalse(output.exists())
                    self.assertFalse(any(p.name.startswith('.historycrate-publish-') for p in self.root.iterdir()))
                finally:
                    target.write_bytes(original)

    def test_owned_ref_symbolic_head_reproduces_native_fsck_rejection(self):
        import subprocess
        with self.job() as job:
            packet, _ = build_packet(self.spec, job)
            verified = verify_packet(packet, job)
            repo = verified.private_root/'imported/repos/source'
            original = (repo/'HEAD').read_bytes()
            (repo/'HEAD').write_text(f'ref: refs/historycrate/commits/{self.tip}\n')
            try:
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    native(repo, 'fsck', '--full', '--strict', '--no-reflogs', '--no-dangling')
                self.assertIn(b'HEAD points to something strange', caught.exception.stderr)
            finally:
                (repo/'HEAD').write_bytes(original)
            self.assertEqual(native(repo, 'fsck', '--full', '--strict', '--no-reflogs', '--no-dangling'), b'')

    def test_create_packet_postpublication_report_failure_keeps_commit_status(self):
        from historycrate import packet as implementation
        output = self.root/'published-packet'
        real_value = implementation.value
        def fail_late_report(closure):
            if output.exists():
                raise RuntimeError('report construction after publication failed')
            return real_value(closure)
        with self.job() as job:
            with mock.patch.object(implementation, 'value', side_effect=fail_late_report):
                with self.assertRaises(CrateError) as caught:
                    implementation.create_packet(self.spec, output, job)
            self.assertEqual(caught.exception.context.get('publication'), 'published-durability-uncertain')
            self.assertEqual(caught.exception.exit_code, 6)
            self.assertTrue((output/'COMPLETE.json').is_file())

    def test_bundle_materialization_preflights_reserve_before_native_write(self):
        from historycrate import monitor
        with self.job() as job:
            run = job.native.run
            fstatvfs = os.fstatvfs
            seeds_installed = False
            bundle_started = False
            def run_and_change_space(operation, parameters, *args, **kwargs):
                nonlocal seeds_installed, bundle_started
                if operation=='bundle_selected':
                    bundle_started = True
                result = run(operation, parameters, *args, **kwargs)
                if operation=='install_seeds':
                    seeds_installed = True
                return result
            def current_space(fd):
                if seeds_installed:
                    return type('Space', (), {'f_bavail': 0, 'f_frsize': 4096})()
                return fstatvfs(fd)
            with mock.patch.object(job.native, 'run', side_effect=run_and_change_space), mock.patch.object(monitor.os, 'fstatvfs', side_effect=current_space):
                with self.assertRaises(CrateError) as caught:
                    build_packet(self.spec, job)
            self.assertEqual(caught.exception.code, 'INSUFFICIENT_SPACE')
            self.assertFalse(bundle_started, 'bundle write began without next-phase free-space admission')

    def test_gitlink_recomputation_counts_each_unique_object_once(self):
        from tests.fixtures.histories import modules
        self.f.repository('child')
        child = self.f.commit('child', {'child-file': b'child'})
        tip = self.f.commit('source', {'.gitmodules': modules(('dep','dep','../child')), 'dep': (0o160000, child)}, (self.tip,))
        spec = self.f.spec([('root','source',(tip,))], [('source','dep','../child','child')])
        with self.job() as builder:
            packet, closure = build_packet(spec, builder)
            total = len(objects(self.f.repos['source'], (tip,)))+len(objects(self.f.repos['child'],(child,)))
            self.assertEqual(total, len(closure.objects))
            with Job(Limits().lower({'git_objects': total}), self.tools) as verifier:
                local = verifier.root/'received'
                shutil.copytree(packet, local)
                verified = verify_packet(local, verifier)
                self.assertEqual(len(verified.closure.objects), total)

    def test_cancellation_after_rename_syscall_preserves_commit_status(self):
        from historycrate import paths
        from historycrate.publication import publish_tree
        with self.job(output_parent=self.root) as job:
            source = job.root/'validated'
            source.mkdir(mode=0o700)
            readonly = source/'readonly'
            readonly.mkdir(mode=0o700)
            (readonly/'bytes').write_bytes(b'verified')
            readonly.chmod(0o555)
            output = self.root/'published'
            rename = paths._rename_noreplace
            interrupted = False
            def interrupt_after_rename(source_fd, source_name, target_fd, target_name):
                nonlocal interrupted
                rename(source_fd, source_name, target_fd, target_name)
                if target_name==output.name:
                    interrupted = True
                    raise KeyboardInterrupt()
            try:
                with mock.patch.object(paths, '_rename_noreplace', side_effect=interrupt_after_rename):
                    with self.assertRaises(CrateError) as caught:
                        publish_tree(source, output, job, job.limits.packet_bytes)
                self.assertTrue(interrupted)
                self.assertEqual(caught.exception.context.get('publication'), 'published-durability-uncertain')
                self.assertEqual((output/'readonly').stat().st_mode & 0o777, 0o555)
                self.assertEqual((output/'readonly/bytes').read_bytes(), b'verified')
            finally:
                readonly.chmod(0o700)
                if output.exists():
                    (output/'readonly').chmod(0o700)
                    shutil.rmtree(output)

    def test_postrename_atomic_descriptor_close_is_preserved_and_reported(self):
        from historycrate import paths
        from historycrate.publication import publish_tree
        import errno
        with self.job(output_parent=self.root) as job:
            source = job.root/'validated'
            source.mkdir(mode=0o700)
            readonly = source/'readonly'
            readonly.mkdir(mode=0o700)
            (readonly/'bytes').write_bytes(b'verified')
            readonly.chmod(0o555)
            output = self.root/'published'
            close = os.close
            failed = False
            def fail_atomic_stage_close(fd):
                nonlocal failed
                info = os.fstat(fd)
                close(fd)
                if not failed and output.exists() and (info.st_dev, info.st_ino)==(output.stat().st_dev, output.stat().st_ino):
                    failed = True
                    raise OSError(errno.EIO, 'postrename atomic stage close')
            try:
                with mock.patch.object(paths.os, 'close', side_effect=fail_atomic_stage_close):
                    with self.assertRaises(CrateError) as caught:
                        publish_tree(source, output, job, job.limits.packet_bytes)
                self.assertTrue(failed)
                self.assertEqual(caught.exception.context.get('publication'), 'published-durability-uncertain')
                self.assertEqual((output/'readonly').stat().st_mode & 0o777, 0o555)
                self.assertEqual((output/'readonly/bytes').read_bytes(), b'verified')
            finally:
                readonly.chmod(0o700)
                if output.exists():
                    (output/'readonly').chmod(0o700)
                    shutil.rmtree(output)

if __name__=='__main__':
    unittest.main()
