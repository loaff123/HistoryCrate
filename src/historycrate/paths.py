"""No-follow filesystem primitives for owned, stable, trusted local data.

Descriptors pin the objects inspected. They do not make the filesystem a
snapshot, prevent the owner from racing operations, or impose a storage quota.
Callers must stop their native children before cleanup or publication.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import secrets
import stat
import tempfile
import time
import unicodedata
from typing import Iterator

from .errors import CrateError


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_MAX_ENTRIES = 1_000_000


def _error(code: str, exit_code: int = 3, **context: object) -> CrateError:
    return CrateError(code, exit_code, context)


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def validate_relative_path(relative: str, *, repository: bool = True) -> tuple[str, ...]:
    """Validate supported UTF-8 paths; punctuation stays opaque filename data.

    ``repository=False`` admits .git metadata names for controller file access.
    It never relaxes traversal, encoding, control-character or size checks.
    """
    if not isinstance(relative, str):
        raise _error("UNSAFE_PATH", reason="path is not text")
    try:
        encoded = relative.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise _error("UNSAFE_PATH", reason="path is not UTF-8") from exc
    parts = relative.split("/")
    if (not relative or len(encoded) > 1024 or len(parts) > 64
            or unicodedata.normalize("NFC", relative) != relative
            or "\\" in relative
            or any(unicodedata.category(c) == "Cc" for c in relative)
            or any(p in ("", ".", "..") or len(p.encode("utf-8")) > 255 for p in parts)
            or (repository and any(p.casefold() == ".git" for p in parts))):
        raise _error("UNSAFE_PATH", reason="unsupported path component")
    return tuple(parts)


def _absolute(path: os.PathLike[str] | str) -> Path:
    # Do not use resolve/realpath: they would silently traverse symlinks.
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise _error("UNSAFE_PATH", reason="invalid filesystem path")
    if ".." in raw.split("/"):
        raise _error("UNSAFE_PATH", reason="parent traversal")
    return Path(os.path.abspath(raw))


def _validate_owned(info: os.stat_result, *, directory: bool) -> None:
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise _error("UNSAFE_FILE_TYPE")
    if info.st_uid != os.geteuid():
        raise _error("UNSAFE_OWNER", expected_uid=os.geteuid(), observed_uid=info.st_uid)
    if info.st_mode & 0o022:
        raise _error("UNSAFE_PERMISSIONS")
    if not directory and info.st_nlink != 1:
        raise _error("UNSAFE_HARDLINK", links=info.st_nlink)


def _open_absolute_directory(path: Path, *, validate_endpoint: bool = True) -> int:
    fd = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if validate_endpoint:
            _validate_owned(os.fstat(fd), directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_directory(path: os.PathLike[str] | str) -> int:
    """Open every component no-follow; validate the owned, non-writable endpoint.

    Root-owned ancestors, including sticky /tmp, are traversal locations, not
    admitted data or output parents. Returned descriptors belong to the caller.
    """
    try:
        absolute = _absolute(path)
        # /tmp is reserved as a scratch ancestor, even on task filesystems that
        # represent it as an owned 0755 directory rather than shared sticky 1777.
        if absolute == Path("/tmp"):
            raise _error("UNSAFE_DIRECTORY", reason="raw temporary directory")
        return _open_absolute_directory(absolute)
    except OSError as exc:
        raise _error("UNSAFE_DIRECTORY", 4 if exc.errno == errno.ENOENT else 3,
                     errno=exc.errno) from exc


def open_regular_beneath(directory_fd: int, relative: str) -> int:
    """Read a single-link owned regular file without following any symlink."""
    parts = validate_relative_path(relative, repository=False)
    fd = os.dup(directory_fd)
    result = None
    try:
        _validate_owned(os.fstat(fd), directory=True)
        for component in parts[:-1]:
            next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            _validate_owned(os.fstat(fd), directory=True)
        # O_NONBLOCK avoids hanging on FIFOs before their type can be refused.
        result = os.open(parts[-1], _FILE_FLAGS, dir_fd=fd)
        _validate_owned(os.fstat(result), directory=False)
        return result
    except BaseException as exc:
        if result is not None:
            os.close(result)
        if isinstance(exc, OSError):
            raise _error("UNSAFE_FILE", 4 if exc.errno == errno.ENOENT else 3,
                         errno=exc.errno) from exc
        raise
    finally:
        os.close(fd)


def _ancestors(fd: int) -> frozenset[tuple[int, int]]:
    seen: set[tuple[int, int]] = set()
    current = os.dup(fd)
    try:
        for _ in range(4096):
            identity = _identity(os.fstat(current))
            if identity in seen:
                return frozenset(seen)
            seen.add(identity)
            parent = os.open("..", _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = parent
        raise _error("PATH_ANCESTRY_LIMIT", 5)
    finally:
        os.close(current)


@dataclass(frozen=True)
class _PathIdentity:
    identity: tuple[int, int] | None
    ancestors: frozenset[tuple[int, int]]
    parent: tuple[int, int]
    name: str


def _path_identity(path: Path) -> _PathIdentity:
    absolute = _absolute(path)
    if absolute == Path("/"):
        fd = open_directory(absolute)
        try:
            identity = _identity(os.fstat(fd))
            return _PathIdentity(identity, frozenset((identity,)), identity, "")
        finally:
            os.close(fd)
    # The parent of an existing input is an ancestry location: root-owned /tmp
    # is allowed here. An absent leaf is a proposed output and gets the strict
    # endpoint-parent checks below.
    parent = _open_absolute_directory(absolute.parent, validate_endpoint=False)
    endpoint = None
    try:
        parent_identity = _identity(os.fstat(parent))
        ancestors = _ancestors(parent)
        try:
            info = os.stat(absolute.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            _validate_owned(os.fstat(parent), directory=True)
            if absolute.parent == Path("/tmp"):
                raise _error("UNSAFE_DIRECTORY", reason="raw temporary directory")
            return _PathIdentity(None, ancestors, parent_identity, absolute.name)
        if stat.S_ISDIR(info.st_mode):
            endpoint = os.open(absolute.name, _DIRECTORY_FLAGS, dir_fd=parent)
            opened = os.fstat(endpoint)
            _validate_owned(opened, directory=True)
            if _identity(opened) != _identity(info):
                raise _error("SOURCE_CHANGED", 4)
            ancestors = _ancestors(endpoint)
        elif stat.S_ISREG(info.st_mode):
            endpoint = open_regular_beneath(parent, absolute.name)
            if _identity(os.fstat(endpoint)) != _identity(info):
                raise _error("SOURCE_CHANGED", 4)
        else:
            raise _error("UNSAFE_FILE_TYPE")
        return _PathIdentity(_identity(info), ancestors, parent_identity, absolute.name)
    finally:
        if endpoint is not None:
            os.close(endpoint)
        os.close(parent)


def assert_disjoint(paths: tuple[Path, ...]) -> None:
    """Reject equality/ancestry by descriptor identity, including absent leaves.

    This general helper intentionally rejects all supplied overlap. Callers
    admitting nested absorbed repositories should compare the protected roles
    (object/cache stores, outputs), not all repository containers indiscriminately.
    """
    try:
        identities = [_path_identity(path) for path in paths]
        for index, first in enumerate(identities):
            for second in identities[index + 1:]:
                if ((first.parent, first.name) == (second.parent, second.name)
                        or (first.identity is not None and
                            (first.identity == second.identity or first.identity in second.ancestors))
                        or (second.identity is not None and second.identity in first.ancestors)):
                    raise _error("PATH_OVERLAP")
    except OSError as exc:
        raise _error("UNSAFE_PATH", 4, errno=exc.errno) from exc


def protected_worktree_root(git_dir: os.PathLike[str] | str) -> Path | None:
    """Conservatively protect the lexical ancestor before the first literal .git.

    This deliberately ignores source configuration, including core.worktree.
    Bare Git directories without a .git component have no path-derived worktree.
    """
    path = _absolute(git_dir)
    try:
        index = path.parts.index(".git")
    except ValueError:
        return None
    return Path(*path.parts[:index])


@dataclass
class PrivateDirectory:
    path: Path
    fd: int
    _preserved: bool = False

    def preserve(self) -> None:
        """Leave scratch intact, e.g. when expected-child exit is unconfirmed."""
        self._preserved = True


def _same_entry(parent: int, name: str, expected: tuple[int, int]) -> None:
    try:
        observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise _error("SOURCE_CHANGED", 4) from exc
    if _identity(observed) != expected or not stat.S_ISDIR(observed.st_mode):
        raise _error("SOURCE_CHANGED", 4)


def _clear_private(fd: int, deadline: float, count: list[int]) -> None:
    with os.scandir(fd) as entries:
        for entry in entries:
            count[0] += 1
            if count[0] > _MAX_ENTRIES or time.monotonic() > deadline:
                raise _error("CLEANUP_LIMIT", 5)
            info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=fd)
                try:
                    _same_entry(fd, entry.name, _identity(os.fstat(child)))
                    _clear_private(child, deadline, count)
                    _same_entry(fd, entry.name, _identity(os.fstat(child)))
                    os.rmdir(entry.name, dir_fd=fd)
                finally:
                    os.close(child)
            else:
                # Unlinking a symlink/hardlink never follows it or edits its target.
                os.unlink(entry.name, dir_fd=fd)


@contextmanager
def private_directory(parent: os.PathLike[str] | str | None = None,
                      prefix: str = ".historycrate-") -> Iterator[PrivateDirectory]:
    """Create mode-0700 scratch and delete only the original unpublished inode.

    A default private root may be created under sticky /tmp. Explicit parents
    must satisfy the stricter owned output-parent policy. No input chmod occurs.
    """
    if not prefix or "/" in prefix or "\0" in prefix:
        raise _error("UNSAFE_PATH")
    parent_path = _absolute(tempfile.gettempdir() if parent is None else parent)
    if parent is None:
        parent_fd = _open_absolute_directory(parent_path, validate_endpoint=False)
        info = os.fstat(parent_fd)
        if not (info.st_uid in (0, os.geteuid()) and
                (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX)):
            os.close(parent_fd)
            raise _error("UNSAFE_TEMP_PARENT")
    else:
        parent_fd = open_directory(parent_path)
    name = prefix + secrets.token_hex(16)
    fd = None
    created = False
    private = None
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created = True
        fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        expected = _identity(os.fstat(fd))
        _validate_owned(os.fstat(fd), directory=True)
        # mkdir's mode may be narrowed by umask; owned scratch needs 0700 exactly.
        try:
            os.fchmod(fd, 0o700)
        except OSError as exc:
            raise _error("PRIVATE_DIRECTORY_SETUP_FAILED", 6, errno=exc.errno) from exc
        private = PrivateDirectory(parent_path / name, fd)
        yield private
    finally:
        try:
            if created and fd is not None and not (private and private._preserved):
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    # Atomic publication moved this directory; never delete output.
                    pass
                else:
                    _same_entry(parent_fd, name, expected)
                    _clear_private(fd, time.monotonic() + 30.0, [0])
                    _same_entry(parent_fd, name, expected)
                    os.rmdir(name, dir_fd=parent_fd)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)


@dataclass(frozen=True)
class FileObservation:
    bytes: int
    files: int
    entries: int
    timestamp: float

    @property
    def regular_bytes(self) -> int:
        return self.bytes


def _walk_regular(fd: int, *, max_entries: int, timeout: float,
                  flush: bool = False) -> FileObservation:
    if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 1:
        raise _error("INVALID_OBSERVATION_LIMIT", 2)
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
        raise _error("INVALID_OBSERVATION_LIMIT", 2)
    started = time.monotonic()
    total = files = entries_seen = 0
    seen: set[tuple[int, int]] = set()

    def visit(current: int, depth: int) -> None:
        nonlocal total, files, entries_seen
        _validate_owned(os.fstat(current), directory=True)
        identity = _identity(os.fstat(current))
        if identity in seen:
            raise _error("FILESYSTEM_ALIAS")
        seen.add(identity)
        if depth > 64:
            raise _error("OBSERVATION_LIMIT", 5, resource="directory_depth")
        with os.scandir(current) as iterator:
            for entry in iterator:
                entries_seen += 1
                if entries_seen > max_entries or time.monotonic() - started > timeout:
                    raise _error("OBSERVATION_LIMIT", 5, entries=entries_seen)
                try:
                    info = os.stat(entry.name, dir_fd=current, follow_symlinks=False)
                except FileNotFoundError:
                    if flush:
                        raise
                    # Native-owned scratch is mutable during observations.
                    # A confirmed vanished name contributes no current bytes;
                    # this is one reason a sample is never a peak-size guarantee.
                    continue
                if stat.S_ISDIR(info.st_mode):
                    try:
                        child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=current)
                    except FileNotFoundError:
                        if flush:
                            raise
                        continue
                    try:
                        if _identity(os.fstat(child)) != _identity(info):
                            raise _error("SOURCE_CHANGED", 4)
                        visit(child, depth + 1)
                    finally:
                        os.close(child)
                else:
                    _validate_owned(info, directory=False)
                    if flush:
                        child = open_regular_beneath(current, entry.name)
                        try:
                            if _identity(os.fstat(child)) != _identity(info):
                                raise _error("SOURCE_CHANGED", 4)
                            os.fsync(child)
                        finally:
                            os.close(child)
                    total += info.st_size
                    files += 1
        if time.monotonic() - started > timeout:
            raise _error("OBSERVATION_LIMIT", 5, entries=entries_seen)
        if flush:
            os.fsync(current)

    visit(fd, 0)
    return FileObservation(total, files, entries_seen, time.monotonic())


def observe_regular_files(path_or_fd: os.PathLike[str] | str | int, *,
                          max_entries: int = _MAX_ENTRIES,
                          timeout: float = 1.0) -> FileObservation:
    """Bounded logical-byte sample, not peak storage usage or an atomic snapshot."""
    fd = os.dup(path_or_fd) if isinstance(path_or_fd, int) else open_directory(path_or_fd)
    try:
        return _walk_regular(fd, max_entries=max_entries, timeout=timeout)
    except OSError as exc:
        raise _error("OBSERVATION_FAILED", 4, errno=exc.errno) from exc
    finally:
        os.close(fd)


def _rename_noreplace(source_fd: int, source: str, destination_fd: int,
                      destination: str) -> None:
    """Linux libc renameat2 binding. Intentionally no rename/replace fallback."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renameat2
    except AttributeError as exc:
        raise OSError(errno.ENOSYS, "renameat2 unavailable") from exc
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(source_fd, os.fsencode(source), destination_fd,
              os.fsencode(destination), 1) != 0:  # RENAME_NOREPLACE
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def check_filesystem_capabilities(parent: os.PathLike[str] | str) -> dict[str, bool]:
    """Exercise case sensitivity and actual no-replace semantics on this device."""
    try:
        with private_directory(parent, prefix=".historycrate-capability-") as probe:
            first = os.open("caseprobe", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                            0o600, dir_fd=probe.fd)
            os.close(first)
            try:
                second = os.open("CASEPROBE", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                                 0o600, dir_fd=probe.fd)
            except FileExistsError as exc:
                raise _error("CASE_INSENSITIVE_FILESYSTEM") from exc
            os.close(second)
            os.mkdir("source", 0o700, dir_fd=probe.fd)
            os.mkdir("destination", 0o700, dir_fd=probe.fd)
            source = _identity(os.stat("source", dir_fd=probe.fd, follow_symlinks=False))
            destination = _identity(os.stat("destination", dir_fd=probe.fd, follow_symlinks=False))
            try:
                _rename_noreplace(probe.fd, "source", probe.fd, "destination")
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
            else:
                raise _error("UNSUPPORTED_NOREPLACE")
            _same_entry(probe.fd, "source", source)
            _same_entry(probe.fd, "destination", destination)
            os.rmdir("destination", dir_fd=probe.fd)
            _rename_noreplace(probe.fd, "source", probe.fd, "destination")
            _same_entry(probe.fd, "destination", source)
        return {"case_sensitive": True, "rename_noreplace": True}
    except OSError as exc:
        raise _error("FILESYSTEM_CAPABILITY_UNAVAILABLE", 3, errno=exc.errno) from exc


def _parent_still_pinned(path: Path, fd: int) -> None:
    reopened = open_directory(path)
    try:
        if _identity(os.fstat(reopened)) != _identity(os.fstat(fd)):
            raise _error("SOURCE_CHANGED", 4)
    finally:
        os.close(reopened)


def atomic_publish(stage: os.PathLike[str] | str,
                   destination: os.PathLike[str] | str) -> None:
    """Flush and no-replace rename an already validated private sibling.

    Native validation and exact verified inventory are the caller's prerequisites.
    The successful rename is the commit point. Every later failure preserves the
    published tree and reports published-durability-uncertain (exit 6).
    """
    source_path, target_path = _absolute(stage), _absolute(destination)
    parent = source_parent = stage_fd = None
    published = False
    rename_attempted = False
    try:
        parent = open_directory(target_path.parent)
        source_parent = open_directory(source_path.parent)
        if _identity(os.fstat(parent)) != _identity(os.fstat(source_parent)):
            raise _error("PUBLICATION_NOT_SIBLINGS", 6, publication="not-published")
        try:
            os.stat(target_path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise _error("DESTINATION_EXISTS", 6, publication="not-published")
        stage_fd = os.open(source_path.name, _DIRECTORY_FLAGS, dir_fd=parent)
        info = os.fstat(stage_fd)
        _validate_owned(info, directory=True)
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise _error("PUBLICATION_NOT_PRIVATE", 6, publication="not-published")
        _walk_regular(stage_fd, max_entries=_MAX_ENTRIES, timeout=300.0, flush=True)
        _parent_still_pinned(target_path.parent, parent)
        _same_entry(parent, source_path.name, _identity(info))
        rename_attempted = True
        _rename_noreplace(parent, source_path.name, parent, target_path.name)
        published = True
        _same_entry(parent, target_path.name, _identity(info))
        os.fsync(parent)
        _parent_still_pinned(target_path.parent, parent)
    except BaseException as exc:
        if rename_attempted and not published:
            # A signal can arrive after the syscall commits but before Python
            # assigns published=True. Reconcile only through the pinned parent;
            # never run unpublished rollback against a possibly published inode.
            try:
                try:
                    target = os.stat(target_path.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    target = None
                try:
                    remaining = os.stat(source_path.name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    remaining = None
                published = ((target is not None and _identity(target) == _identity(info))
                             or remaining is None or _identity(remaining) != _identity(info))
            except BaseException:
                # The original stage cannot be proven unpublished. Preserve it
                # conservatively, with the same uncertain commit/durability result.
                published = True
        if published:
            raise _error("PUBLISHED_DURABILITY_UNCERTAIN", 6,
                         publication="published-durability-uncertain") from exc
        if isinstance(exc, OSError):
            raise _error("PUBLICATION_FAILED", 6, errno=exc.errno,
                         publication="not-published") from exc
        raise
    finally:
        # Closing a descriptor can fail after the rename commit point too.
        # Attempt all closes without allowing teardown to lose that status.
        close_failure = None
        for fd in (stage_fd, source_parent, parent):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as exc:
                    close_failure = exc
        if close_failure is not None:
            if published:
                raise _error("PUBLISHED_DURABILITY_UNCERTAIN", 6,
                             publication="published-durability-uncertain") from close_failure
            raise _error("PUBLICATION_FAILED", 6,
                         publication="not-published", errno=getattr(close_failure, 'errno', None)) from close_failure
