"""Controller-only publication using original disposable directory fixtures."""
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import errno
import importlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job, qualify_toolchain

ROOT = Path(__file__).resolve().parents[1]


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(TEST_GIT,
                                     TEST_LFS, Limits())

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.publication'),
                             'validated-tree controller publication is missing')
        self.pub = importlib.import_module('historycrate.publication')
        self.paths = importlib.import_module('historycrate.paths')
        self.temp = tempfile.TemporaryDirectory(prefix='historycrate-publication-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.job = Job(Limits(), self.tools, output_parent=self.base)
        self.job.__enter__()
        self.addCleanup(self.job.__exit__, None, None, None)
        self.source = self.job.root/'validated'
        self.source.mkdir(mode=0o700)
        self.output = self.base/'output'

    def file(self, name='nested/it\'s :safe', data=b'fully validated bytes', mode=0o644):
        path = self.source/name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def publish(self, maximum=None):
        return self.pub.publish_tree(self.source, self.output, self.job,
                                     self.job.limits.packet_bytes if maximum is None else maximum)

    def assert_refused(self, action=None, code=None, publication='not-published'):
        with self.assertRaises(CrateError) as caught:
            (action or self.publish)()
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(caught.exception.context['publication'], publication)
        return caught.exception

    def assert_no_partial(self):
        self.assertEqual(set(self.base.iterdir()), {self.job.root})

    def test_controller_copy_preserves_exact_bytes_modes_and_empty_directories(self):
        original = self.file(mode=0o755)
        self.file('.git/objects/ab/file', b'objects', 0o444)
        (self.source/'empty').mkdir(mode=0o750)
        before = original.stat()
        records = len(self.job.native.records)
        with mock.patch.object(self.job.native, 'run', side_effect=AssertionError('native publication forbidden')):
            report = self.publish()
        self.assertEqual(report.publication, 'published')
        self.assertEqual(report.bytes, len(original.read_bytes()) + 7)
        self.assertEqual(report.files, 2)
        self.assertEqual(report.directories, 6)
        self.assertEqual((self.output/"nested/it's :safe").read_bytes(), original.read_bytes())
        self.assertEqual(stat.S_IMODE((self.output/"nested/it's :safe").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.output/'.git/objects/ab/file').stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((self.output/'empty').stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(original.stat().st_ino, before.st_ino)
        self.assertNotEqual(original.stat().st_ino, (self.output/"nested/it's :safe").stat().st_ino)
        self.assertEqual(self.job.external_materialized_bytes, 0)
        self.assertEqual(len(self.job.native.records), records)

    def test_preexisting_directory_and_dangling_symlink_are_preserved(self):
        self.file()
        self.output.mkdir(mode=0o700)
        keep = self.output/'keep'
        keep.write_bytes(b'original')
        self.assert_refused(code='DESTINATION_EXISTS')
        self.assertEqual(keep.read_bytes(), b'original')
        keep.unlink(); self.output.rmdir()
        self.output.symlink_to('missing')
        self.assert_refused(code='DESTINATION_EXISTS')
        self.assertTrue(self.output.is_symlink())

    def test_source_and_output_ancestry_are_refused(self):
        self.file()
        for output in (self.source, self.source/'inside', self.job.root/'inside'):
            with self.subTest(output=output):
                self.output = output
                self.assert_refused()
        self.assertTrue(self.source.exists())

    def test_original_sources_worktrees_caches_and_packet_input_are_protected(self):
        self.file()
        worktree = self.base/'original'
        (worktree/'.git/objects').mkdir(mode=0o700, parents=True)
        cache = self.base/'cache'; cache.mkdir(mode=0o700)
        packet = self.base/'packet'; packet.mkdir(mode=0o700)
        self.job.source_paths = (worktree/'.git',)
        self.job._lfs_source_paths = (cache,)
        self.job._packet_source_paths = (packet,)
        for protected in (worktree, worktree/'.git/objects', cache, packet):
            with self.subTest(protected=protected):
                self.output = protected/'new'
                self.assert_refused(code='PATH_OVERLAP')
                self.assertFalse(self.output.exists())

    def test_source_must_be_owned_job_scratch(self):
        self.source = self.base/'external'
        self.source.mkdir(mode=0o700)
        self.file()
        self.assert_refused(code='PUBLICATION_SOURCE_NOT_SCRATCH')
        self.assertFalse(self.output.exists())

    def test_symlink_hardlink_fifo_and_special_mode_refused(self):
        item = self.file('bad')
        item.unlink(); item.symlink_to('/etc/passwd')
        self.assert_refused(); item.unlink()
        outside = self.base/'outside'; outside.write_bytes(b'external')
        os.link(outside, item)
        self.assert_refused(); item.unlink(); outside.unlink()
        os.mkfifo(item, mode=0o600)
        self.assert_refused(); item.unlink()
        self.file('bad', mode=0o4600)
        self.assert_refused(); item.unlink()
        self.assert_no_partial()

    def test_exact_final_size_is_admitted_before_copy(self):
        self.file(data=b'abcd')
        self.assert_refused(lambda: self.publish(3), code='BUDGET_EXCEEDED')
        self.assert_no_partial()
        self.assertEqual(self.publish(4).bytes, 4)

    def test_combined_scratch_and_output_budget_includes_full_copy(self):
        self.file(data=b'abcd')
        self.job.limits = self.job.limits.lower({'combined_bytes': 7})
        self.assert_refused(code='BUDGET_EXCEEDED')
        self.assert_no_partial()

    def test_insufficient_free_space_reserve_blocks_before_copy(self):
        self.file()
        space = type('Space', (), {'f_bavail': 1, 'f_frsize': 4096})()
        with mock.patch.object(self.pub.os, 'fstatvfs', return_value=space):
            self.assert_refused(code='INSUFFICIENT_SPACE')
        self.assert_no_partial()

    def test_no_replace_capability_missing_is_error(self):
        self.file()
        with mock.patch.object(self.paths, '_rename_noreplace', side_effect=OSError(errno.ENOSYS, 'unsupported')):
            self.assert_refused(code='FILESYSTEM_CAPABILITY_UNAVAILABLE')
        self.assert_no_partial()

    def test_destination_creation_race_preserves_other_directory(self):
        self.file()
        rename = self.paths._rename_noreplace
        def race(source_fd, source, target_fd, target):
            if target == self.output.name:
                self.output.mkdir(mode=0o700)
                (self.output/'keep').write_bytes(b'racing owner')
            return rename(source_fd, source, target_fd, target)
        with mock.patch.object(self.paths, '_rename_noreplace', side_effect=race):
            self.assert_refused()
        self.assertEqual((self.output/'keep').read_bytes(), b'racing owner')
        self.assertEqual(set(self.base.iterdir()), {self.job.root, self.output})

    def test_postrename_parent_fsync_failure_preserves_valid_output(self):
        self.file()
        fsync = os.fsync
        parent_identity = (self.base.stat().st_dev, self.base.stat().st_ino)
        def fail_parent(fd):
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) == parent_identity:
                raise OSError(errno.EIO, 'postcommit failure')
            return fsync(fd)
        with mock.patch.object(self.paths.os, 'fsync', side_effect=fail_parent):
            error = self.assert_refused(code='PUBLISHED_DURABILITY_UNCERTAIN',
                                       publication='published-durability-uncertain')
        self.assertEqual(error.exit_code, 6)
        self.assertEqual((self.output/"nested/it's :safe").read_bytes(), b'fully validated bytes')
        self.assertEqual(set(self.base.iterdir()), {self.job.root, self.output})


    def test_precommit_failure_cleans_read_only_owned_copy_directories(self):
        self.file('readonly/file')
        readonly = self.source/'readonly'
        readonly.chmod(0o555)
        self.addCleanup(readonly.chmod, 0o700)
        with mock.patch.object(self.paths, 'atomic_publish', side_effect=OSError(errno.EIO, 'precommit failure')):
            self.assert_refused()
        self.assert_no_partial()
        self.assertEqual(stat.S_IMODE(readonly.stat().st_mode), 0o555)

    def test_postcommit_descriptor_close_failure_is_typed_and_preserves_output(self):
        self.file()
        close = os.close
        source_identity = (self.source.stat().st_dev, self.source.stat().st_ino)
        failed = False
        def fail_close(fd):
            nonlocal failed
            info = os.fstat(fd)
            close(fd)
            if not failed and self.output.exists() and (info.st_dev, info.st_ino) == source_identity:
                failed = True
                raise OSError(errno.EIO, 'close failure')
        with mock.patch.object(self.pub.os, 'close', side_effect=fail_close):
            self.assert_refused(code='PUBLISHED_DURABILITY_UNCERTAIN',
                                publication='published-durability-uncertain')
        self.assertTrue(failed)
        self.assertEqual((self.output/"nested/it's :safe").read_bytes(), b'fully validated bytes')

    def test_prepublication_interruption_disk_full_and_fsync_leave_no_final_output(self):
        self.file()
        for error in (KeyboardInterrupt(), OSError(errno.ENOSPC, 'disk full')):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(self.pub, '_write_all', side_effect=error):
                    self.assert_refused()
                self.assert_no_partial()
                self.assertEqual(self.job.external_materialized_bytes, 0)
                self.assertFalse(self.job.native.busy)
        with mock.patch.object(self.paths.os, 'fsync', side_effect=OSError(errno.EIO, 'sync failure')):
            self.assert_refused()
        self.assert_no_partial()

    def test_source_mutation_during_copy_is_refused(self):
        item = self.file()
        write = self.pub._write_all
        def mutate(fd, data):
            write(fd, data)
            item.write_bytes(b'x' * len(data))
        with mock.patch.object(self.pub, '_write_all', side_effect=mutate):
            self.assert_refused(code='SOURCE_CHANGED')
        self.assert_no_partial()

    def test_copy_inventory_detects_extra_file_byte_corruption_and_mode_change(self):
        self.file()
        copy = self.pub._copy
        def alter(kind):
            def wrapped(source, target, inventory, job, monitor, directory_ids):
                copy(source, target, inventory, job, monitor, directory_ids)
                if kind == 'extra':
                    fd = os.open('extra', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target)
                    os.close(fd)
                else:
                    fd = os.open("nested/it's :safe", os.O_WRONLY, dir_fd=target)
                    try:
                        if kind == 'bytes':
                            os.write(fd, b'x')
                        else:
                            os.fchmod(fd, 0o700)
                    finally:
                        os.close(fd)
            return wrapped
        for kind in ('extra', 'bytes', 'mode'):
            with self.subTest(kind=kind):
                with mock.patch.object(self.pub, '_copy', side_effect=alter(kind)):
                    self.assert_refused(code='PUBLICATION_COPY_MISMATCH')
                self.assert_no_partial()

    def test_postcommit_report_failure_preserves_valid_output(self):
        self.file()
        with mock.patch.object(self.pub, 'PublicationReport', side_effect=RuntimeError('report failure')):
            self.assert_refused(code='PUBLISHED_DURABILITY_UNCERTAIN',
                                publication='published-durability-uncertain')
        self.assertEqual((self.output/"nested/it's :safe").read_bytes(), b'fully validated bytes')

    def test_active_native_or_uncertain_child_exit_blocks_publication(self):
        self.file()
        self.job.native.busy = True
        self.assert_refused(code='PUBLICATION_NATIVE_ACTIVE')
        self.assertTrue(self.job.native.busy)
        self.job.native.busy = False
        self.job.native.records.append({'observations': {'cleanup': {'uncertain': True}}})
        self.assert_refused(code='PUBLICATION_CHILD_EXIT_UNCERTAIN')
        self.assert_no_partial()

    def test_destination_parent_replacement_preserves_new_parent(self):
        self.file()
        parent = self.base/'parent'; parent.mkdir(mode=0o700)
        self.output = parent/'output'
        moved = self.base/'moved-parent'
        rename = self.paths._rename_noreplace
        def replace(source_fd, source, target_fd, target):
            if target == 'output':
                parent.rename(moved)
                parent.mkdir(mode=0o700)
                (parent/'keep').write_bytes(b'unrelated')
            return rename(source_fd, source, target_fd, target)
        with mock.patch.object(self.paths, '_rename_noreplace', side_effect=replace):
            self.assert_refused(code='PUBLISHED_DURABILITY_UNCERTAIN',
                                publication='published-durability-uncertain')
        self.assertEqual((parent/'keep').read_bytes(), b'unrelated')
        self.assertFalse(self.output.exists())
        self.assertEqual((moved/"output/nested/it's :safe").read_bytes(), b'fully validated bytes')

    def test_replaced_source_path_is_refused_without_following_replacement(self):
        self.file()
        old_source = self.source
        moved = self.job.root/'moved-source'
        copy = self.pub._copy
        def replace(*args):
            copy(*args)
            old_source.rename(moved)
            old_source.mkdir(mode=0o700)
            (old_source/'keep').write_bytes(b'untouched replacement')
        with mock.patch.object(self.pub, '_copy', side_effect=replace):
            self.assert_refused(code='SOURCE_CHANGED')
        self.assertEqual((old_source/'keep').read_bytes(), b'untouched replacement')
        self.assertFalse(self.output.exists())
        self.assert_no_partial()

    def test_final_fsync_covers_every_file_and_directory_before_commit(self):
        self.file()
        self.file('.git/config', b'fixed configuration')
        (self.source/'empty').mkdir(mode=0o700)
        synced = set()
        sync = os.fsync
        rename = self.paths._rename_noreplace
        def record(fd):
            info = os.fstat(fd)
            synced.add((info.st_dev, info.st_ino))
            return sync(fd)
        def verify_then_rename(source_fd, source, target_fd, target):
            if target == self.output.name:
                stage = self.base/source
                entries = [stage, *stage.rglob('*')]
                self.assertTrue(all((entry.stat().st_dev, entry.stat().st_ino) in synced for entry in entries))
            return rename(source_fd, source, target_fd, target)
        with mock.patch.object(self.paths.os, 'fsync', side_effect=record), mock.patch.object(self.paths, '_rename_noreplace', side_effect=verify_then_rename):
            self.publish()
        self.assertIn((self.base.stat().st_dev, self.base.stat().st_ino), synced)

    def test_invalid_maximum_and_lowered_path_limits_refuse(self):
        self.file()
        for maximum in (True, -1, self.job.limits.packet_bytes + 1):
            with self.subTest(maximum=maximum):
                self.assert_refused(lambda: self.publish(maximum), code='INVALID_LIMIT')
        for overrides in ({'path_depth': 1}, {'path_bytes': 3}, {'component_bytes': 2}):
            self.job.limits = Limits().lower(overrides)
            self.assert_refused(code='BUDGET_EXCEEDED')
            self.assert_no_partial()

    def test_active_native_refusal_requests_preservation_of_job_scratch(self):
        self.file()
        self.job.native.busy = True
        error = self.assert_refused(code='PUBLICATION_NATIVE_ACTIVE')
        self.assertTrue(error.context.get('cleanup_uncertain'))
        self.job.native.busy = False

    def test_atomic_helper_close_failure_preserves_published_directory_modes(self):
        self.file()
        (self.source/'nested').chmod(0o755)
        close = os.close
        failed = False
        def fail_close(fd):
            nonlocal failed
            info = os.fstat(fd)
            close(fd)
            if not failed and self.output.exists():
                output_info = self.output.stat()
                if (info.st_dev, info.st_ino) == (output_info.st_dev, output_info.st_ino):
                    failed = True
                    raise OSError(errno.EIO, 'atomic helper stage close failure')
        with mock.patch.object(self.paths.os, 'close', side_effect=fail_close):
            self.assert_refused(code='PUBLISHED_DURABILITY_UNCERTAIN',
                                publication='published-durability-uncertain')
        self.assertTrue(failed)
        self.assertEqual(stat.S_IMODE((self.output/'nested').stat().st_mode), 0o755)
        self.assertEqual((self.output/"nested/it's :safe").read_bytes(), b'fully validated bytes')

    def test_final_external_source_check_can_block_after_copy_before_commit(self):
        self.file()
        outside = self.base/'original.git'; outside.mkdir(mode=0o700)
        sentinel = outside/'sentinel'; sentinel.write_bytes(b'original source')
        self.job.source_paths = (outside,)
        copy = self.pub._copy
        checked = []
        def mutate(*args):
            copy(*args)
            sentinel.write_bytes(b'changed source')
        def recheck():
            checked.append(True)
            self.assertFalse(self.output.exists())
            self.assertTrue(self.job.native.busy)
            if sentinel.read_bytes() != b'original source':
                raise CrateError('SOURCE_CHANGED', 4)
        self.job._prepublication_checks = (recheck,)
        with mock.patch.object(self.pub, '_copy', side_effect=mutate):
            self.assert_refused(code='SOURCE_CHANGED')
        self.assertEqual(checked, [True])
        self.assertEqual(set(self.base.iterdir()), {self.job.root, outside})

    def test_interrupt_between_successful_rename_and_status_assignment_is_preserved(self):
        self.file()
        (self.source/'nested').chmod(0o755)
        rename = self.paths._rename_noreplace
        def interrupt_after(source_fd, source, target_fd, target):
            rename(source_fd, source, target_fd, target)
            if target == self.output.name:
                raise KeyboardInterrupt()
        with mock.patch.object(self.paths, '_rename_noreplace', side_effect=interrupt_after):
            self.assert_refused(code='PUBLISHED_DURABILITY_UNCERTAIN',
                                publication='published-durability-uncertain')
        self.assertEqual(stat.S_IMODE((self.output/'nested').stat().st_mode), 0o755)
        self.assertEqual((self.output/"nested/it's :safe").read_bytes(), b'fully validated bytes')

    def test_atomic_return_interrupt_receipt_preserves_published_modes(self):
        self.file(); (self.source/'nested').chmod(0o755)
        atomic=self.paths.atomic_publish
        def interrupt_after(*args):
            atomic(*args)
            raise KeyboardInterrupt('after atomic helper returned')
        with mock.patch.object(self.paths,'atomic_publish',side_effect=interrupt_after):
            self.assert_refused(code='PUBLISHED_DURABILITY_UNCERTAIN',
                                publication='published-durability-uncertain')
        self.assertEqual(stat.S_IMODE((self.output/'nested').stat().st_mode),0o755)
        self.assertEqual((self.output/"nested/it's :safe").read_bytes(),b'fully validated bytes')
        self.assertEqual(self.pub.publication_status(self.job),'published-durability-uncertain')

    def test_receipt_checkpoints_do_not_taint_later_precommit_failures(self):
        self.assertTrue(callable(getattr(self.pub,'publication_checkpoint',None)),
                        'persistent publication receipts are missing')
        self.file(); before=self.pub.publication_checkpoint(self.job)
        self.publish()
        self.assertEqual(self.pub.publication_status(self.job,since=before),'published')
        after=self.pub.publication_checkpoint(self.job)
        self.assert_refused(code='DESTINATION_EXISTS')
        self.assertEqual(self.pub.publication_status(self.job,since=after),'not-published')
        self.output=self.base/'second'
        with mock.patch.object(self.paths,'atomic_publish',side_effect=KeyboardInterrupt()):
            self.assert_refused(code='CANCELLED')
        self.assertEqual(self.pub.publication_status(self.job,since=after),'not-published')
        self.assertFalse(self.output.exists())
        self.assertEqual(self.pub.publication_status(self.job),'published')

    def test_completed_receipt_does_not_follow_later_destination_replacements(self):
        self.assertTrue(callable(getattr(self.pub,'publication_status',None)),
                        'persistent publication receipts are missing')
        self.file(); self.publish()
        self.output.rename(self.base/'published-original')
        self.output.mkdir(); (self.output/'unrelated').write_bytes(b'leave alone')
        self.assertEqual(self.pub.publication_status(self.job),'published')
        self.assertEqual((self.output/'unrelated').read_bytes(),b'leave alone')


if __name__ == '__main__':
    unittest.main()
