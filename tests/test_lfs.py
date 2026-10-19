"""Fail-closed LFS parsing, local payload copying, and descriptor hydration."""
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS
import dataclasses
import hashlib
import importlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.model import Closure, LfsOccurrence, PayloadRecord, RepoSpec
from historycrate.native import Job, qualify_toolchain
from tests.fixtures.lfs_cases import (LFS_ATTRIBUTES, ORDINARY_ATTRIBUTES, PAYLOAD,
                                      cache_file, pointer, write_cache)

ROOT = Path(__file__).resolve().parents[1]


def occurrence(repository='main', payload=PAYLOAD, *, size=None, sha256=None, path='file'):
    digest = hashlib.sha256(payload).hexdigest() if sha256 is None else sha256
    return LfsOccurrence(repository, 'a' * 40, path, 'b' * 40, digest,
                         len(payload) if size is None else size)


def closure(*items):
    return Closure((), {}, {}, (), (), (), tuple(items))


class _LfsCase(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.lfs'),
                             'LFS pointer and payload implementation is missing')
        self.lfs = importlib.import_module('historycrate.lfs')


class LfsParserTests(_LfsCase):
    def test_pointer_requires_effective_lfs_attribute(self):
        value = pointer()
        self.assertIsNone(self.lfs.parse_lfs_blob(value, ORDINARY_ATTRIBUTES))
        self.assertIsNone(self.lfs.parse_lfs_blob(value, {'filter': 'unset'}))
        self.assertIsNone(self.lfs.parse_lfs_blob(value, {}))
        self.assertEqual(self.lfs.parse_lfs_blob(value, LFS_ATTRIBUTES),
                         (hashlib.sha256(PAYLOAD).hexdigest(), len(PAYLOAD)))

    def test_empty_lfs_blob_is_empty_file(self):
        self.assertIsNone(self.lfs.parse_lfs_blob(b'', LFS_ATTRIBUTES))

    def test_zero_size_pointer_is_refused(self):
        with self.assertRaises(CrateError) as caught:
            self.lfs.parse_lfs_blob(pointer(b''), LFS_ATTRIBUTES)
        self.assertEqual(caught.exception.code, 'LFS_ZERO_SIZE_POINTER')

    def test_noncanonical_or_extended_pointer_refused(self):
        p = pointer()
        malformed = [b'ordinary data', p[:-1], p + b'\n', p.replace(b'\n', b'\r\n'),
                     p.replace(b'size ', b'size 0'), p.replace(b'size ', b'size +'),
                     p.replace(b'sha256:', b'sha1:'), p.replace(b'oid ', b'oid  '),
                     p.replace(b'\nsize ', b'\next-0-demo abc\nsize '),
                     p.replace(b'\nsize ', b'\nunknown x\nsize '),
                     p.replace(b'\nsize ', b'\noid sha256:' + b'a'*64 + b'\nsize '),
                     p.replace(hashlib.sha256(PAYLOAD).hexdigest().encode(), b'A'*64),
                     b'\xef\xbb\xbf' + p, p + b'\xff']
        for blob in malformed:
            with self.subTest(blob=repr(blob)):
                with self.assertRaises(CrateError):
                    self.lfs.parse_lfs_blob(blob, LFS_ATTRIBUTES)
                self.assertIsNone(self.lfs.parse_lfs_blob(blob, ORDINARY_ATTRIBUTES))

    def test_lfs_requires_unset_text_and_no_transformations(self):
        for key, values in {'text':['set', 'auto', 'unspecified', 'false'],
                            'eol':['lf', 'crlf', 'set'], 'ident':['set', 'false'],
                            'working-tree-encoding':['UTF-8', 'UTF-16']}.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    attrs = dict(LFS_ATTRIBUTES, **{key:value})
                    with self.assertRaises(CrateError):
                        self.lfs.parse_lfs_blob(pointer(), attrs)
                    with self.assertRaises(CrateError):
                        self.lfs.parse_lfs_blob(b'', attrs)
        for value in ['custom', 'set', 'LFS']:
            with self.assertRaises(CrateError):
                self.lfs.parse_lfs_blob(pointer(), dict(LFS_ATTRIBUTES, filter=value))

    def test_pointer_1024_byte_boundary_is_admission_not_capture(self):
        prefix = pointer(size=1).rsplit(b'1\n', 1)[0]
        exact = prefix + b'1' * (1024-len(prefix)-1) + b'\n'
        self.assertEqual(len(exact), 1024)
        self.assertEqual(self.lfs.parse_lfs_blob(exact, LFS_ATTRIBUTES)[1],
                         int(b'1' * (1024-len(prefix)-1)))
        with self.assertRaises(CrateError) as caught:
            self.lfs.parse_lfs_blob(exact[:-1] + b'1\n', LFS_ATTRIBUTES)
        self.assertEqual(caught.exception.exit_code, 5)


class LfsPayloadTests(_LfsCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(TEST_GIT,
                                     TEST_LFS, Limits())

    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory(prefix='historycrate-lfs-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base/'source.git'
        (self.source/'objects').mkdir(parents=True, mode=0o700)
        self.cache = self.source/'lfs/objects'
        self.repo = RepoSpec('main', self.source, self.cache)
        self.job = Job(Limits(), self.tools, output_parent=self.base)
        self.job.__enter__()
        self.addCleanup(self.job.__exit__, None, None, None)

    def collect(self, *items, repositories=None):
        return self.lfs.collect_payloads(closure(*(items or (occurrence(),))),
                                         repositories or (self.repo,), self.job)

    def lower(self, **limits):
        from historycrate.limits import Budget
        self.job.limits = self.job.limits.lower(limits)
        self.job.budget = Budget(self.job.limits)
        self.job.native.limits = self.job.limits

    def test_no_payload_does_not_require_or_search_any_cache(self):
        self.assertEqual(self.lfs.collect_payloads(closure(), (self.repo,), self.job).records, ())
        self.assertFalse(self.cache.exists())

    def test_payload_fresh_copy_and_source_bytes_unchanged(self):
        src = write_cache(self.cache)
        before = src.read_bytes()
        records = self.collect().records
        self.assertEqual(len(records), 1)
        result = records[0]
        self.assertEqual((result.sha256, result.size),
                         (hashlib.sha256(PAYLOAD).hexdigest(), len(PAYLOAD)))
        self.assertEqual(result.private_path.read_bytes(), PAYLOAD)
        self.assertNotEqual((src.stat().st_dev, src.stat().st_ino),
                            (result.private_path.stat().st_dev, result.private_path.stat().st_ino))
        self.assertEqual(result.private_path.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(result.private_path.stat().st_mode), 0o600)
        self.assertEqual(src.read_bytes(), before)
        self.assertEqual(self.job.budget.used['unique_lfs_bytes'], len(PAYLOAD))

    def test_missing_corrupt_size_mismatch_payload_blocks(self):
        for content in [None, b'x' * len(PAYLOAD), PAYLOAD[:-1], PAYLOAD+b'x']:
            with self.subTest(content=content):
                if content is not None:
                    write_cache(self.cache, content, sha256=occurrence().sha256)
                with self.assertRaises(CrateError):
                    self.collect()
                self.assertFalse(any(self.job.root.glob('lfs-payloads-*')))
        write_cache(self.cache)
        self.assertEqual(self.collect().records[0].private_path.read_bytes(), PAYLOAD)

    def test_payload_symlink_hardlink_and_nonregular_refused(self):
        src = write_cache(self.cache)
        other = self.base/'other'
        src.rename(other)
        src.symlink_to(other)
        with self.assertRaises(CrateError): self.collect()
        src.unlink()
        os.link(other, src)
        with self.assertRaises(CrateError): self.collect()
        src.unlink()
        os.mkfifo(src, mode=0o600)
        with self.assertRaises(CrateError): self.collect()
        self.assertEqual(other.read_bytes(), PAYLOAD)

    def test_cache_and_fanout_symlinks_refused(self):
        src = write_cache(self.cache)
        fanout = src.parent
        moved = self.base/'fanout'
        fanout.rename(moved)
        fanout.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(CrateError): self.collect()
        fanout.unlink(); moved.rename(fanout)
        moved = self.base/'moved-cache'
        self.cache.rename(moved)
        self.cache.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(CrateError): self.collect()

    def test_group_writable_source_files_and_directories_refused(self):
        src = write_cache(self.cache)
        for path in [src, src.parent, self.cache]:
            original = stat.S_IMODE(path.stat().st_mode)
            path.chmod(original | 0o020)
            with self.assertRaises(CrateError): self.collect()
            path.chmod(original)

    def test_cross_repository_dedup_checks_every_source_and_same_size(self):
        write_cache(self.cache)
        child = self.base/'child.git'
        (child/'objects').mkdir(parents=True, mode=0o700)
        second = RepoSpec('child', child, child/'lfs/objects')
        with self.assertRaises(CrateError):
            self.collect(occurrence(), occurrence('child'), repositories=(self.repo,second))
        write_cache(second.lfs_objects_dir, b'x'*len(PAYLOAD), sha256=occurrence().sha256)
        with self.assertRaises(CrateError):
            self.collect(occurrence(), occurrence('child'), repositories=(self.repo,second))
        write_cache(second.lfs_objects_dir)
        self.lower(unique_lfs_bytes=len(PAYLOAD))
        got = self.collect(occurrence(), occurrence('child'), occurrence(path='again'),
                           repositories=(self.repo,second))
        self.assertEqual(len(got.records), 1)
        self.assertEqual(self.job.budget.used['unique_lfs_bytes'], len(PAYLOAD))
        with self.assertRaises(CrateError) as caught:
            self.collect(occurrence(), occurrence('child', size=len(PAYLOAD)+1),
                         repositories=(self.repo,second))
        self.assertEqual(caught.exception.code, 'LFS_CONFLICTING_SIZE')

    def test_shared_cache_alias_and_object_store_overlap_refused(self):
        write_cache(self.cache)
        child = self.base/'child.git'
        (child/'objects').mkdir(parents=True, mode=0o700)
        second = RepoSpec('child', child, self.cache)
        with self.assertRaises(CrateError):
            self.collect(occurrence(), occurrence('child'), repositories=(self.repo,second))
        write_cache(child/'objects')
        overlap = dataclasses.replace(self.repo, lfs_objects_dir=child/'objects')
        second = dataclasses.replace(second, lfs_objects_dir=child/'lfs/objects')
        write_cache(second.lfs_objects_dir)
        with self.assertRaises(CrateError):
            self.collect(occurrence(), occurrence('child'), repositories=(overlap, second))

    def test_only_explicit_cache_is_consulted(self):
        write_cache(self.cache)
        explicit = dataclasses.replace(self.repo, lfs_objects_dir=self.base/'explicit')
        with self.assertRaises(CrateError): self.collect(repositories=(explicit,))
        write_cache(explicit.lfs_objects_dir)
        self.assertEqual(self.collect(repositories=(explicit,)).records[0].private_path.read_bytes(), PAYLOAD)

    def test_lowered_single_payload_and_unique_total_limits(self):
        write_cache(self.cache)
        self.lower(lfs_payload_bytes=len(PAYLOAD)-1)
        with self.assertRaises(CrateError) as caught: self.collect()
        self.assertEqual(caught.exception.exit_code, 5)

    def test_lowered_unique_total_streaming_charge_and_cleanup(self):
        write_cache(self.cache)
        other = b'other authored payload'
        write_cache(self.cache, other)
        self.lower(unique_lfs_bytes=len(PAYLOAD)+len(other)-1)
        with self.assertRaises(CrateError) as caught:
            self.collect(occurrence(), occurrence(payload=other))
        self.assertEqual(caught.exception.context['resource'], 'unique_lfs_bytes')
        self.assertFalse(any(self.job.root.glob('lfs-payloads-*')))

    def test_lowered_scratch_threshold_blocks_and_cleans(self):
        write_cache(self.cache)
        self.lower(scratch_bytes=len(PAYLOAD)-1)
        with self.assertRaises(CrateError) as caught: self.collect()
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertFalse(any(self.job.root.glob('lfs-payloads-*')))

    def test_source_replacement_during_copy_fails_without_retry(self):
        src = write_cache(self.cache)
        original_read = os.read
        replaced = False
        def read(fd, amount):
            nonlocal replaced
            data = original_read(fd, amount)
            st = os.fstat(fd)
            if data and not replaced and (st.st_dev, st.st_ino) == (src.stat().st_dev, src.stat().st_ino):
                replaced = True
                temporary = src.with_name('replacement')
                temporary.write_bytes(PAYLOAD)
                os.replace(temporary, src)
            return data
        with patch('historycrate.lfs.os.read', side_effect=read):
            with self.assertRaises(CrateError) as caught: self.collect()
        self.assertTrue(replaced)
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
        self.assertFalse(any(self.job.root.glob('lfs-payloads-*')))

    def test_source_directory_addition_during_copy_is_detected(self):
        src = write_cache(self.cache)
        original_read = os.read
        changed = False
        def read(fd, amount):
            nonlocal changed
            data = original_read(fd, amount)
            if data and not changed and os.fstat(fd).st_ino == src.stat().st_ino:
                changed = True
                (src.parent/'added').write_bytes(b'new source entry')
            return data
        with patch('historycrate.lfs.os.read', side_effect=read):
            with self.assertRaises(CrateError) as caught: self.collect()
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')

    def test_hydrate_fresh_regular_preserves_mode_and_literal_distinction(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        for name, mode in [(':wq', 0o100644), ("apostrophe'file",0o100755),
                           ('space name',0o100644), ('-leading',0o100644)]:
            self.lfs.hydrate_file(fd, name, mode, payload, self.job)
            self.assertEqual((target/name).read_bytes(), PAYLOAD)
            self.assertEqual(stat.S_IMODE((target/name).stat().st_mode), mode & 0o777)
            self.assertNotEqual((target/name).stat().st_ino, payload.private_path.stat().st_ino)
        (target/'literal').write_bytes(pointer())
        self.assertIsNone(self.lfs.parse_lfs_blob((target/'literal').read_bytes(), ORDINARY_ATTRIBUTES))
        self.assertEqual((target/'literal').read_bytes(), pointer())
        (target/'pointer').write_bytes(pointer())
        self.lfs.hydrate_file(fd, 'pointer', 0o100644, payload, self.job)
        self.assertEqual((target/'pointer').read_bytes(), PAYLOAD)

    def test_hydrate_rejects_existing_alias_and_bad_names(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        victim = self.base/'victim'
        victim.write_bytes(b'preserve')
        (target/'link').symlink_to(victim)
        os.link(victim, target/'hard')
        for name in ['link', 'hard', '../victim', 'a/b', '.git']:
            with self.subTest(name=name):
                with self.assertRaises(CrateError):
                    self.lfs.hydrate_file(fd, name, 0o100644, payload, self.job)
        with self.assertRaises(CrateError):
            self.lfs.hydrate_file(fd, 'mode', 0o120000, payload, self.job)
        self.assertEqual(victim.read_bytes(), b'preserve')

    def test_hydrate_rechecks_payload_hash_and_preserves_existing_on_failure(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        (target/'file').write_bytes(pointer())
        payload.private_path.write_bytes(b'x'*payload.size)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self.assertRaises(CrateError):
            self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertEqual((target/'file').read_bytes(), pointer())
        self.assertEqual(sorted(x.name for x in target.iterdir()), ['file'])

    def test_hydrate_lowered_restore_budget_cleans_partial(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.lower(restore_bytes=len(PAYLOAD)-1)
        with self.assertRaises(CrateError) as caught:
            self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(list(target.iterdir()), [])

    def test_native_lfs_clean_and_fsck_agree_with_authored_bytes(self):
        native = self.job.native
        native.run('init', {'name':'native-lfs', 'bare':False})
        got = native.run('lfs_clean', {'repo':'native-lfs', 'path':'file'}, PAYLOAD).stdout
        self.assertEqual(got, pointer())
        self.assertEqual(native.run('lfs_clean', {'repo':'native-lfs', 'path':'empty'}, b'').stdout, b'')
        self.assertEqual(self.lfs.parse_lfs_blob(got, LFS_ATTRIBUTES),
                         (hashlib.sha256(PAYLOAD).hexdigest(), len(PAYLOAD)))
        attr = native.run('hash_blob', {'repo':'native-lfs', 'write':True},
                          b'file filter=lfs -text\nempty filter=lfs -text\n').stdout.strip().decode()
        blob = native.run('hash_blob', {'repo':'native-lfs', 'write':True}, got).stdout.strip().decode()
        empty = native.run('hash_blob', {'repo':'native-lfs', 'write':True}, b'').stdout.strip().decode()
        tree = native.run('make_tree', {'repo':'native-lfs'},
                          f'100644 blob {attr}\t.gitattributes\0'
                          f'100644 blob {empty}\tempty\0'
                          f'100644 blob {blob}\tfile\0'.encode()).stdout.strip().decode()
        commit = native.run('commit_tree', {'repo':'native-lfs','tree':tree,'parents':()}, b'fixture\n').stdout.strip().decode()
        native.run('update_ref', {'repo':'native-lfs','oid':commit})
        native.run('fsck', {'repo':'native-lfs'})
        native.run('lfs_fsck', {'repo':'native-lfs','commit':commit})
        cache = self.job.root/'repos/native-lfs/.git/lfs/objects'
        stored = cache_file(cache)
        self.assertEqual(stored.read_bytes(), PAYLOAD)
        stored.unlink()
        with self.assertRaises(CrateError):
            native.run('lfs_fsck', {'repo':'native-lfs','commit':commit})
        write_cache(cache)
        native.run('lfs_fsck', {'repo':'native-lfs','commit':commit})

    def test_hydrate_rejects_temporary_path_replacement_before_publish(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        (target/'file').write_bytes(pointer())
        victim = self.base/'victim'
        victim.write_bytes(b'unchanged')
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        original_fsync = os.fsync
        replaced = False
        def fsync(stream):
            nonlocal replaced
            result = original_fsync(stream)
            files = list(target.glob('.historycrate-lfs-*'))
            if files and not replaced:
                replaced = True
                files[0].unlink()
                files[0].symlink_to(victim)
            return result
        with patch('historycrate.lfs.os.fsync', side_effect=fsync):
            with self.assertRaises(CrateError) as caught:
                self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertTrue(replaced)
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
        self.assertEqual((target/'file').read_bytes(), pointer())
        self.assertFalse((target/'file').is_symlink())
        self.assertEqual(victim.read_bytes(), b'unchanged')

    def test_hydrate_lowered_zero_path_depth_is_refused(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.lower(path_depth=0)
        with self.assertRaises(CrateError) as caught:
            self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(list(target.iterdir()), [])

    def test_hydration_cannot_target_a_declared_source_directory(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        self.job.source_paths = (self.source, self.cache)
        (self.source/'file').write_bytes(b'source bytes')
        fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self.assertRaises(CrateError):
            self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertEqual((self.source/'file').read_bytes(), b'source bytes')

    def test_source_removal_during_copy_is_source_changed(self):
        src = write_cache(self.cache)
        original_read = os.read
        removed = False
        identity = src.stat().st_ino
        def read(fd, amount):
            nonlocal removed
            data = original_read(fd, amount)
            if data and not removed and os.fstat(fd).st_ino == identity:
                removed = True
                src.unlink()
            return data
        with patch('historycrate.lfs.os.read', side_effect=read):
            with self.assertRaises(CrateError) as caught: self.collect()
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')

    def test_missing_payload_diagnostic_identifies_exact_occurrence(self):
        self.cache.mkdir(parents=True, mode=0o700)
        with self.assertRaises(CrateError) as caught: self.collect()
        self.assertEqual(caught.exception.code, 'LFS_MISSING_PAYLOAD')
        self.assertEqual(caught.exception.context['repository'], 'main')
        self.assertEqual(caught.exception.context['sha256'], occurrence().sha256)
        self.assertEqual(caught.exception.context['commit'], 'a'*40)
        self.assertEqual(caught.exception.context['path'], 'file')

    def test_hydrate_cleanup_does_not_remove_replaced_temporary_inode(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        original_fsync = os.fsync
        replacement = []
        def fsync(stream):
            result = original_fsync(stream)
            files = list(target.glob('.historycrate-lfs-*'))
            if files and not replacement:
                files[0].unlink()
                files[0].write_bytes(b'unowned replacement content')
                replacement.append(files[0])
            return result
        with patch('historycrate.lfs.os.fsync', side_effect=fsync):
            with self.assertRaises(CrateError):
                self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertTrue(replacement[0].exists())
        self.assertEqual(replacement[0].read_bytes(), b'unowned replacement content')
        self.assertFalse((target/'file').exists())

    def test_unused_repository_paths_are_not_opened(self):
        write_cache(self.cache)
        unused = RepoSpec('unused', self.base/'missing-parent/repo.git',
                          self.base/'missing-parent/cache')
        original_stat = os.stat
        def checked_stat(path, *args, **kwargs):
            if 'missing-parent' in os.fspath(path):
                self.fail('An unused repository path was accessed')
            return original_stat(path, *args, **kwargs)
        with patch('historycrate.lfs.os.stat', side_effect=checked_stat):
            got = self.collect(repositories=(self.repo, unused))
        self.assertEqual(len(got.records), 1)

    def test_collect_refuses_job_scratch_inside_active_source(self):
        write_cache(self.cache)
        with Job(Limits(), self.tools, output_parent=self.source) as unsafe:
            with self.assertRaises(CrateError):
                self.lfs.collect_payloads(closure(occurrence()), (self.repo,), unsafe)
            self.assertFalse(any(unsafe.root.glob('lfs-payloads-*')))

    def test_hydrate_combined_budget_counts_in_scratch_file_once(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.job.root/'work'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.lower(combined_bytes=2*len(PAYLOAD), scratch_bytes=2*len(PAYLOAD),
                   restore_bytes=len(PAYLOAD))
        try:
            self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        except CrateError as exc:
            self.fail(f'Exact actual combined byte limit was incorrectly refused: {exc.code}')
        self.assertEqual((target/'file').read_bytes(), PAYLOAD)
        self.assertEqual(self.job.budget.used['restore_bytes'], len(PAYLOAD))

    def test_streaming_counts_real_chunks_and_exact_lowered_limit(self):
        src = write_cache(self.cache)
        self.lower(lfs_payload_bytes=len(PAYLOAD), unique_lfs_bytes=len(PAYLOAD))
        original_read = os.read
        charges = []
        inode = src.stat().st_ino
        def read(fd, amount):
            if os.fstat(fd).st_ino == inode:
                charges.append(self.job.budget.used.get('unique_lfs_bytes', 0))
            return original_read(fd, amount)
        with patch('historycrate.lfs._CHUNK', 8), patch('historycrate.lfs.os.read', side_effect=read):
            result = self.collect().records[0]
        self.assertEqual(result.private_path.read_bytes(), PAYLOAD)
        self.assertEqual(charges, list(range(0, len(PAYLOAD), 8)) + [len(PAYLOAD)])
        self.assertEqual(self.job.budget.used['unique_lfs_bytes'], len(PAYLOAD))

    def test_controller_rss_and_watchdog_limits_are_real(self):
        write_cache(self.cache)
        for limits in [{'observed_rss_bytes': 1}, {'job_wall_seconds': 0},
                       {'observation_entries': 0}, {'combined_bytes': len(PAYLOAD)-1}]:
            with self.subTest(limits=limits):
                with Job(Limits().lower(limits), self.tools, output_parent=self.base) as job:
                    with self.assertRaises(CrateError) as caught:
                        self.lfs.collect_payloads(closure(occurrence()), (self.repo,), job)
                    self.assertEqual(caught.exception.exit_code, 5)
                    self.assertFalse(any(job.root.glob('lfs-payloads-*')))

    def test_insufficient_space_and_write_failure_cleanup(self):
        import errno
        from types import SimpleNamespace
        write_cache(self.cache)
        with patch('historycrate.lfs.os.fstatvfs', return_value=SimpleNamespace(f_bavail=1, f_frsize=1)):
            with self.assertRaises(CrateError) as caught: self.collect()
        self.assertEqual(caught.exception.code, 'INSUFFICIENT_SPACE')
        self.assertFalse(any(self.job.root.glob('lfs-payloads-*')))
        with patch('historycrate.lfs.os.write', side_effect=OSError(errno.ENOSPC, 'fixture full')):
            with self.assertRaises(CrateError): self.collect()
        self.assertFalse(any(self.job.root.glob('lfs-payloads-*')))
        self.assertEqual(cache_file(self.cache).read_bytes(), PAYLOAD)

    def test_native_pointer_payloads_are_not_clean_roundtrip_admissible(self):
        nested = pointer(b'inner payload')
        variants = [nested, nested.replace(b'https://git-lfs.github.com/spec/v1', b'http://git-media.io/v/2'),
                    nested.replace(b'\n', b'\r\n'), nested + b' ' * (1023-len(nested))]
        for data in variants:
            with self.subTest(data=data[:50]):
                write_cache(self.cache, data)
                with self.assertRaises(CrateError) as caught:
                    self.collect(occurrence(payload=data))
                self.assertEqual(caught.exception.code, 'LFS_CLEAN_ROUNDTRIP_FAILED')
                self.assertFalse(any(self.job.root.glob('lfs-payloads-*')))

    def test_native_pointer_recognition_cutoff_and_literal_markers(self):
        native = self.job.native
        native.run('init', {'name':'cutoff', 'bare':False})
        nested = pointer(b'inner payload')
        for data in [nested + b' '*(1024-len(nested)), nested + b' '*(1025-len(nested)),
                     b'ordinary git-lfs marker, not a pointer']:
            with self.subTest(size=len(data)):
                actual = native.run('lfs_clean', {'repo':'cutoff', 'path':'file'}, data).stdout
                self.assertEqual(actual, pointer(data))
                write_cache(self.cache, data)
                result = self.collect(occurrence(payload=data)).records[0]
                self.assertEqual(result.private_path.read_bytes(), data)

    def test_direct_collect_registers_git_source_hydration_guard(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        (self.source/'file').write_bytes(b'source bytes')
        fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        with self.assertRaises(CrateError):
            self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertEqual((self.source/'file').read_bytes(), b'source bytes')

    def test_external_hydration_counts_combined_bytes_without_scratch_charge(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.base/'output'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.lower(scratch_bytes=len(PAYLOAD), combined_bytes=2*len(PAYLOAD))
        self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertEqual((target/'file').read_bytes(), PAYLOAD)
        self.assertEqual(getattr(self.job, 'external_materialized_bytes', 0), len(PAYLOAD))
        with self.assertRaises(CrateError) as caught:
            self.lfs.hydrate_file(fd, 'second', 0o100644, payload, self.job)
        self.assertEqual(caught.exception.context['resource'], 'combined_bytes')
        self.assertFalse((target/'second').exists())

    def test_external_hydration_replacement_counts_peak_then_releases_old_bytes(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.base/'output'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.lower(scratch_bytes=len(PAYLOAD), combined_bytes=3*len(PAYLOAD))
        for _ in range(2):
            self.lfs.hydrate_file(fd, 'file', 0o100644, payload, self.job)
        self.assertEqual(getattr(self.job, 'external_materialized_bytes', 0), len(PAYLOAD))
        self.assertEqual((target/'file').read_bytes(), PAYLOAD)

    def test_external_failed_hydration_releases_only_its_partial_allocation(self):
        write_cache(self.cache)
        payload = self.collect().records[0]
        target = self.base/'output'
        target.mkdir(mode=0o700)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.lfs.hydrate_file(fd, 'first', 0o100644, payload, self.job)
        payload.private_path.write_bytes(b'x'*payload.size)
        with self.assertRaises(CrateError):
            self.lfs.hydrate_file(fd, 'second', 0o100644, payload, self.job)
        self.assertEqual(getattr(self.job, 'external_materialized_bytes', 0), len(PAYLOAD))
        self.assertEqual(sorted(p.name for p in target.iterdir()), ['first'])

    def test_source_fanout_replacement_after_open_is_source_changed(self):
        src = write_cache(self.cache)
        identity = src.stat().st_ino
        original_read = os.read
        changed = False
        def read(fd, amount):
            nonlocal changed
            data = original_read(fd, amount)
            if data and not changed and os.fstat(fd).st_ino == identity:
                changed = True
                moved = self.base/'moved-fanout'
                src.parent.rename(moved)
                src.parent.symlink_to(moved, target_is_directory=True)
            return data
        with patch('historycrate.lfs.os.read', side_effect=read):
            with self.assertRaises(CrateError) as caught: self.collect()
        self.assertEqual(caught.exception.code, 'SOURCE_CHANGED')
