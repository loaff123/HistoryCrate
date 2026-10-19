"""Original, disposable filesystem fixtures for the trusted-local profile."""
import importlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


class PathsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("historycrate.paths"),
                             "descriptor-relative filesystem foundation is missing")
        self.paths = importlib.import_module("historycrate.paths")
        self.CrateError = importlib.import_module("historycrate.errors").CrateError
        self.tmp = tempfile.TemporaryDirectory(prefix="historycrate-path-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def directory(self, name):
        result = self.root / name
        result.mkdir(mode=0o700, parents=True)
        return result

    def file(self, name, content=b"bytes"):
        result = self.root / name
        result.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        result.write_bytes(content)
        result.chmod(0o600)
        return result

    def open_root(self):
        fd = self.paths.open_directory(self.root)
        self.addCleanup(os.close, fd)
        return fd

    def test_directory_descriptor_is_owned_and_noninheritable(self):
        fd = self.open_root()
        self.assertEqual(os.fstat(fd).st_ino, self.root.stat().st_ino)
        self.assertFalse(os.get_inheritable(fd))

    def test_directory_symlink_component_is_refused(self):
        self.directory("real/child")
        (self.root / "alias").symlink_to("real", target_is_directory=True)
        for relative in ("alias", "alias/child"):
            with self.subTest(relative=relative), self.assertRaises(self.CrateError):
                self.paths.open_directory(self.root / relative)

    def test_directory_group_writable_endpoint_is_refused_unchanged(self):
        child = self.directory("unsafe")
        child.chmod(0o770)
        with self.assertRaises(self.CrateError):
            self.paths.open_directory(child)
        self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o770)

    def test_raw_tmp_output_parent_is_refused(self):
        with self.assertRaises(self.CrateError):
            self.paths.open_directory(Path("/tmp"))

    def test_ownership_check_is_on_open_descriptor(self):
        actual = os.geteuid()
        with mock.patch.object(self.paths.os, "geteuid", return_value=actual + 1):
            with self.assertRaises(self.CrateError):
                self.paths.open_directory(self.root)

    def test_punctuation_files_remain_data(self):
        fd = self.open_root()
        for name in (":wq", "it's a file", "-leading-option", "nested/a b"):
            self.file(name, name.encode())
            item = self.paths.open_regular_beneath(fd, name)
            try:
                self.assertEqual(os.read(item, 1024), name.encode())
                self.assertFalse(os.get_inheritable(item))
            finally:
                os.close(item)

    def test_regular_file_rejects_traversal_absolute_and_invalid_components(self):
        fd = self.open_root()
        for name in ("", "/etc/passwd", "../escape", "a/../b", "a//b", "./a",
                     "a/", "a\\b", "a\x00b", "a\nb", "e\u0301"):
            with self.subTest(name=name), self.assertRaises(self.CrateError):
                self.paths.open_regular_beneath(fd, name)

    def test_file_symlink_and_symlink_parent_are_refused(self):
        self.file("real/data")
        (self.root / "file-link").symlink_to("real/data")
        (self.root / "dir-link").symlink_to("real", target_is_directory=True)
        fd = self.open_root()
        for relative in ("file-link", "dir-link/data"):
            with self.subTest(relative=relative), self.assertRaises(self.CrateError):
                self.paths.open_regular_beneath(fd, relative)

    def test_hardlinks_are_refused(self):
        original = self.file("original")
        os.link(original, self.root / "alias")
        with self.assertRaises(self.CrateError):
            self.paths.open_regular_beneath(self.open_root(), "original")

    def test_group_writable_file_and_parent_are_refused(self):
        item = self.file("child/data")
        item.chmod(0o660)
        with self.assertRaises(self.CrateError):
            self.paths.open_regular_beneath(self.open_root(), "child/data")
        item.chmod(0o600)
        item.parent.chmod(0o770)
        with self.assertRaises(self.CrateError):
            self.paths.open_regular_beneath(self.open_root(), "child/data")

    def test_fifo_and_directory_are_refused_without_blocking(self):
        os.mkfifo(self.root / "fifo", mode=0o600)
        self.directory("directory")
        for name in ("fifo", "directory"):
            with self.subTest(name=name), self.assertRaises(self.CrateError):
                self.paths.open_regular_beneath(self.open_root(), name)

    def test_descriptor_pinning_does_not_follow_replaced_path(self):
        original = self.directory("original")
        self.file("original/file", b"original")
        fd = self.paths.open_directory(original)
        self.addCleanup(os.close, fd)
        original.rename(self.root / "moved")
        original.symlink_to(self.directory("replacement"), target_is_directory=True)
        item = self.paths.open_regular_beneath(fd, "file")
        try:
            self.assertEqual(os.read(item, 20), b"original")
        finally:
            os.close(item)

    def test_repository_path_validation_refuses_git_and_bounds(self):
        for name in (".git/config", "x/.GiT/HEAD", "a/" * 64 + "a", "x" * 256,
                     "/".join(["x" * 255] * 5)):
            with self.subTest(name=name), self.assertRaises(self.CrateError):
                self.paths.validate_relative_path(name)
        self.assertEqual(self.paths.validate_relative_path("-safe/it's :fine"),
                         ("-safe", "it's :fine"))

    def test_disjoint_accepts_siblings_and_prefix_lookalikes(self):
        a = self.directory("a")
        ab = self.directory("ab")
        self.paths.assert_disjoint((a, ab, self.root / "future"))

    def test_disjoint_allows_owned_inputs_directly_under_tmp(self):
        with tempfile.TemporaryDirectory(prefix="historycrate-other-") as other:
            self.paths.assert_disjoint((self.root, Path(other)))

    def test_disjoint_rejects_equal_and_ancestor_both_orders(self):
        parent = self.directory("source")
        child = self.directory("source/objects")
        for pair in ((parent, parent), (parent, child), (child, parent),
                     (parent, parent / "new"), (self.root / "new", self.root / "new")):
            with self.subTest(pair=pair), self.assertRaises(self.CrateError):
                self.paths.assert_disjoint(pair)

    def test_disjoint_rejects_symlink_alias(self):
        target = self.directory("target")
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(self.CrateError):
            self.paths.assert_disjoint((target, alias))

    def test_git_path_protects_entire_worktree_without_config(self):
        git = self.directory("worktree/.git/modules/a")
        protected = self.paths.protected_worktree_root(git)
        self.assertEqual(protected, self.root / "worktree")
        with self.assertRaises(self.CrateError):
            self.paths.assert_disjoint((protected, protected / "output"))
        self.assertIsNone(self.paths.protected_worktree_root(self.directory("bare.git")))

    def test_private_directory_is_mode_0700_and_removed(self):
        with self.paths.private_directory(self.root) as private:
            path = private.path
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            (path / "file").write_bytes(b"temporary")
            self.assertEqual(os.fstat(private.fd).st_ino, path.stat().st_ino)
        self.assertFalse(path.exists())

    def test_default_private_directory_under_temp_is_private(self):
        with self.paths.private_directory() as private:
            path = private.path
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertFalse(path.exists())

    def test_private_setup_failure_cleans_created_directory(self):
        before = set(self.root.iterdir())
        with mock.patch.object(self.paths.os, "fchmod", side_effect=OSError("write failure")):
            with self.assertRaises(self.CrateError):
                with self.paths.private_directory(self.root):
                    self.fail("setup must not yield on chmod failure")
        self.assertEqual(set(self.root.iterdir()), before)

    def test_observation_tolerates_confirmed_disappearing_scratch_file(self):
        item = self.file("temporary", b"gone")
        actual_stat = self.paths.os.stat

        def disappeared(path, *args, **kwargs):
            if path == "temporary" and kwargs.get("dir_fd") is not None:
                item.unlink()
            return actual_stat(path, *args, **kwargs)

        with mock.patch.object(self.paths.os, "stat", side_effect=disappeared):
            observation = self.paths.observe_regular_files(self.root)
        self.assertEqual(observation.bytes, 0)
        self.assertEqual(observation.entries, 1)

    def test_publication_rejects_disappearing_file_in_final_inventory(self):
        stage = self.directory("stage")
        item = self.file("stage/temporary", b"gone")
        actual_stat = self.paths.os.stat

        def disappeared(path, *args, **kwargs):
            if path == "temporary" and kwargs.get("dir_fd") is not None:
                item.unlink()
            return actual_stat(path, *args, **kwargs)

        with mock.patch.object(self.paths.os, "stat", side_effect=disappeared):
            with self.assertRaises(self.CrateError):
                self.paths.atomic_publish(stage, self.root / "final")
        self.assertFalse((self.root / "final").exists())

    def test_private_cleanup_preserves_replacement_inode(self):
        with self.assertRaises(self.CrateError):
            with self.paths.private_directory(self.root) as private:
                path = private.path
                path.rename(self.root / "moved")
                path.mkdir(mode=0o700)
                (path / "keep").write_bytes(b"unrelated")
        self.assertEqual((path / "keep").read_bytes(), b"unrelated")

    def test_private_scratch_can_be_preserved_when_child_exit_is_uncertain(self):
        with self.paths.private_directory(self.root) as private:
            path, fd = private.path, private.fd
            (path / "keep").write_bytes(b"inspect")
            private.preserve()
        self.assertEqual((path / "keep").read_bytes(), b"inspect")
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_private_cleanup_unlinks_symlink_without_following(self):
        external = self.directory("external")
        self.file("external/keep", b"keep")
        with self.paths.private_directory(self.root) as private:
            (private.path / "link").symlink_to(external, target_is_directory=True)
        self.assertEqual((external / "keep").read_bytes(), b"keep")

    def test_regular_file_observation_counts_logical_bytes(self):
        self.file("a", b"123")
        self.file("child/b", b"45678")
        observation = self.paths.observe_regular_files(self.root)
        self.assertEqual((observation.bytes, observation.files, observation.entries), (8, 2, 3))
        self.assertGreater(observation.timestamp, 0)
        self.assertEqual(self.paths.observe_regular_files(self.open_root()).bytes, 8)

    def test_observation_entry_budget_fails_closed(self):
        self.file("a")
        self.file("b")
        with self.assertRaises(self.CrateError) as raised:
            self.paths.observe_regular_files(self.root, max_entries=1)
        self.assertEqual(raised.exception.exit_code, 5)

    def test_observation_time_budget_fails_closed(self):
        self.file("a")
        with mock.patch.object(self.paths.time, "monotonic", side_effect=[0, 2, 3, 4]):
            with self.assertRaises(self.CrateError) as raised:
                self.paths.observe_regular_files(self.root, timeout=1)
        self.assertEqual(raised.exception.exit_code, 5)

    def test_observation_refuses_symlinks_hardlinks_and_special_files(self):
        tree = self.directory("tree")
        (tree / "link").symlink_to(self.root / "absent")
        with self.assertRaises(self.CrateError):
            self.paths.observe_regular_files(tree)
        (tree / "link").unlink()
        self.file("tree/a")
        os.link(tree / "a", tree / "b")
        with self.assertRaises(self.CrateError):
            self.paths.observe_regular_files(tree)
        (tree / "a").unlink()
        (tree / "b").unlink()
        os.mkfifo(tree / "fifo", mode=0o600)
        with self.assertRaises(self.CrateError):
            self.paths.observe_regular_files(tree)

    def test_case_sensitivity_and_no_replace_are_actually_probed(self):
        before = set(self.root.iterdir())
        result = self.paths.check_filesystem_capabilities(self.root)
        self.assertTrue(result["case_sensitive"])
        self.assertTrue(result["rename_noreplace"])
        self.assertEqual(set(self.root.iterdir()), before)

    def test_missing_no_replace_capability_fails_closed(self):
        import errno
        with mock.patch.object(self.paths, "_rename_noreplace", side_effect=OSError(errno.ENOSYS, "unsupported")):
            with self.assertRaises(self.CrateError):
                self.paths.check_filesystem_capabilities(self.root)

    def test_atomic_publication_moves_verified_sibling(self):
        stage = self.directory("stage")
        self.file("stage/it's :fine", b"complete")
        self.paths.atomic_publish(stage, self.root / "-final")
        self.assertFalse(stage.exists())
        self.assertEqual((self.root / "-final/it's :fine").read_bytes(), b"complete")

    def test_atomic_publication_preserves_preexisting_destination(self):
        stage = self.directory("stage")
        final = self.directory("final")
        self.file("final/keep", b"original")
        with self.assertRaises(self.CrateError):
            self.paths.atomic_publish(stage, final)
        self.assertEqual((final / "keep").read_bytes(), b"original")
        self.assertTrue(stage.exists())

    def test_atomic_publication_preserves_racing_destination(self):
        stage = self.directory("stage")
        final = self.root / "final"
        rename = self.paths._rename_noreplace

        def race(source_fd, source, destination_fd, destination):
            final.mkdir(mode=0o700)
            (final / "keep").write_bytes(b"racer")
            return rename(source_fd, source, destination_fd, destination)

        with mock.patch.object(self.paths, "_rename_noreplace", side_effect=race):
            with self.assertRaises(self.CrateError) as raised:
                self.paths.atomic_publish(stage, final)
        self.assertEqual(raised.exception.exit_code, 6)
        self.assertEqual((final / "keep").read_bytes(), b"racer")
        self.assertTrue(stage.exists())

    def test_atomic_publication_refuses_dangling_destination_symlink(self):
        stage = self.directory("stage")
        final = self.root / "final"
        final.symlink_to("absent")
        with self.assertRaises(self.CrateError):
            self.paths.atomic_publish(stage, final)
        self.assertTrue(final.is_symlink())

    def test_atomic_publication_requires_same_pinned_parent(self):
        stage = self.directory("stage")
        parent = self.directory("other")
        with self.assertRaises(self.CrateError):
            self.paths.atomic_publish(stage, parent / "final")
        self.assertTrue(stage.exists())

    def test_atomic_publication_never_redirects_through_replaced_parent(self):
        parent = self.directory("parent")
        stage = self.directory("parent/stage")
        self.file("parent/stage/complete", b"complete")
        moved = self.root / "moved-parent"
        rename = self.paths._rename_noreplace

        def replace_parent(source_fd, source, destination_fd, destination):
            parent.rename(moved)
            parent.mkdir(mode=0o700)
            (parent / "keep").write_bytes(b"unrelated")
            return rename(source_fd, source, destination_fd, destination)

        with mock.patch.object(self.paths, "_rename_noreplace", side_effect=replace_parent):
            with self.assertRaises(self.CrateError) as raised:
                self.paths.atomic_publish(stage, parent / "final")
        self.assertEqual(raised.exception.context["publication"], "published-durability-uncertain")
        self.assertEqual((parent / "keep").read_bytes(), b"unrelated")
        self.assertFalse((parent / "final").exists())
        self.assertEqual((moved / "final/complete").read_bytes(), b"complete")

    def test_precommit_fsync_failure_leaves_destination_absent(self):
        stage = self.directory("stage")
        final = self.root / "final"
        self.file("stage/complete", b"complete")
        with mock.patch.object(self.paths.os, "fsync", side_effect=OSError("disk error")):
            with self.assertRaises(self.CrateError) as raised:
                self.paths.atomic_publish(stage, final)
        self.assertEqual(raised.exception.exit_code, 6)
        self.assertFalse(final.exists())
        self.assertTrue(stage.exists())

    def test_postcommit_fsync_failure_preserves_published_output(self):
        stage = self.directory("stage")
        final = self.root / "final"
        self.file("stage/complete", b"complete")
        actual_fsync = os.fsync
        parent_identity = (self.root.stat().st_dev, self.root.stat().st_ino)

        def fail_parent(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == parent_identity:
                raise OSError("post-commit sync error")
            return actual_fsync(fd)

        with mock.patch.object(self.paths.os, "fsync", side_effect=fail_parent):
            with self.assertRaises(self.CrateError) as raised:
                self.paths.atomic_publish(stage, final)
        self.assertEqual(raised.exception.exit_code, 6)
        self.assertEqual(raised.exception.context["publication"], "published-durability-uncertain")
        self.assertFalse(stage.exists())
        self.assertEqual((final / "complete").read_bytes(), b"complete")


if __name__ == "__main__":
    unittest.main()
