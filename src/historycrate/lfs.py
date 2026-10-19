"""Exact historical LFS pointers and read-only, verified local payload copies.

Only explicit cache paths are read. Native LFS is never used for acquisition
or hydration. No atomic source snapshot or hard aggregate resource cap is
claimed: observed changes fail rather than being retried.
"""
from __future__ import annotations

from contextlib import ExitStack
import errno
import hashlib
import os
from pathlib import Path
import re
import secrets

from .errors import CrateError
from .model import PayloadRecord, PayloadSet
from .paths import (_ancestors, _validate_owned, assert_disjoint, open_directory,
                    open_regular_beneath, private_directory, protected_worktree_root,
                    validate_relative_path)
from .monitor import CopyMonitor as _Monitor

_POINTER = re.compile(rb'version https://git-lfs\.github\.com/spec/v1\n'
                      rb'oid sha256:([0-9a-f]{64})\nsize (0|[1-9][0-9]*)\n\Z')
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_CHUNK = 1024 * 1024
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _fail(code, status=4, **context):
    raise CrateError(code, status, context)


def parse_lfs_blob(blob: bytes, effective_attributes: dict[str, str]) -> tuple[str, int] | None:
    """Interpret only effective LFS content; ordinary pointer-like bytes stay data."""
    if not isinstance(blob, bytes) or not isinstance(effective_attributes, dict):
        _fail('INVALID_LFS_INPUT', 2)
    driver = effective_attributes.get('filter', 'unspecified')
    if driver in ('unspecified', 'unset'):
        return None
    if driver != 'lfs':
        _fail('UNSUPPORTED_FILTER', 3)
    if (effective_attributes.get('text', 'unspecified') != 'unset'
            or any(effective_attributes.get(key, 'unspecified') not in ('unspecified', 'unset')
                   for key in ('eol', 'ident', 'working-tree-encoding'))):
        _fail('UNSUPPORTED_LFS_ATTRIBUTES', 3)
    if not blob:
        return None
    if len(blob) > 1024:
        _fail('BUDGET_EXCEEDED', 5, resource='pointer_bytes', threshold=1024)
    matched = _POINTER.fullmatch(blob)
    if matched is None:
        _fail('NONCANONICAL_LFS_POINTER', 3)
    size = int(matched[2])
    if size == 0:
        _fail('LFS_ZERO_SIZE_POINTER', 3)
    return matched[1].decode('ascii'), size


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def _payload_identity(sha256, size, job):
    if (not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None
            or type(size) is not int or size <= 0):
        _fail('INVALID_LFS_PAYLOAD', 3)
    if size > job.limits.lfs_payload_bytes:
        _fail('BUDGET_EXCEEDED', 5, resource='lfs_payload_bytes',
              threshold=job.limits.lfs_payload_bytes, requested=size)


def _preflight_counter(job, resource, amount):
    used = job.budget.used.get(resource, 0)
    if amount > getattr(job.limits, resource) - used:
        _fail('BUDGET_EXCEEDED', 5, resource=resource,
              threshold=getattr(job.limits, resource), used=used, requested=amount)


def _cache_open(root_fd, digest):
    """Pin an exact cache object and its intermediate metadata, no scanning."""
    pieces = (digest[:2], digest[2:4], digest)
    current = os.dup(root_fd)
    snapshots = {}
    prefix = []
    try:
        for index, name in enumerate(pieces):
            prefix.append(name)
            before = os.stat(name, dir_fd=current, follow_symlinks=False)
            directory = index < 2
            _validate_owned(before, directory=directory)
            opened = os.open(name, _DIR_FLAGS if directory else _FILE_FLAGS, dir_fd=current)
            try:
                info = os.fstat(opened)
                _validate_owned(info, directory=directory)
                if _signature(before) != _signature(info):
                    _fail('SOURCE_CHANGED')
            except BaseException:
                os.close(opened)
                raise
            os.close(current)
            current = opened
            snapshots['/'.join(prefix)] = _signature(info)
        result = current
        current = None
        return result, snapshots
    finally:
        if current is not None:
            os.close(current)


def _cache_check(root_fd, digest, expected):
    try:
        fd, observed = _cache_open(root_fd, digest)
    except (OSError, CrateError):
        _fail('SOURCE_CHANGED')
    try:
        if observed != expected:
            _fail('SOURCE_CHANGED')
    finally:
        os.close(fd)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            _fail('LFS_WRITE_FAILED', 6)
        view = view[count:]


def _copy_verified(source_fd, destination_fd, digest, size, job, monitor, resource=None, *, external=False):
    before = _signature(os.fstat(source_fd))
    if before[2] != size:
        _fail('LFS_SIZE_MISMATCH')
    seen = 0
    hasher = hashlib.sha256()
    while True:
        monitor.check()
        block = os.read(source_fd, min(_CHUNK, size - seen + 1))
        if not block:
            break
        seen += len(block)
        if seen > size or seen > job.limits.lfs_payload_bytes:
            _fail('LFS_SIZE_MISMATCH')
        if resource is not None:
            job.budget.charge(resource, len(block))
        hasher.update(block)
        if destination_fd is not None:
            _write_all(destination_fd, block)
            if external:
                job.external_materialized_bytes = getattr(job, 'external_materialized_bytes', 0) + len(block)
        monitor.check()
    if _signature(os.fstat(source_fd)) != before:
        _fail('SOURCE_CHANGED')
    if seen != size:
        _fail('LFS_SIZE_MISMATCH')
    if hasher.hexdigest() != digest:
        _fail('LFS_HASH_MISMATCH')


def _qualify_clean_roundtrip(payload, job):
    """Refuse native-recognized pointer payloads that would clean differently.

    This bounded probe is pinned to qualified LFS 3.8.0. Its copyToTemp only
    short-circuits recognized pointers below BlobSizeCutoff (1024), and its
    decoder first requires git-media, hawser, or git-lfs in the bytes. See the
    pinned upstream source references in the Task 5 qualification evidence.
    No large payload is loaded into memory or passed through native clean.
    """
    if payload.size > 1024:
        return
    parent = open_directory(payload.private_path.parent)
    source = None
    try:
        source = open_regular_beneath(parent, payload.private_path.name)
        before = _signature(os.fstat(source))
        data = bytearray()
        while len(data) <= payload.size:
            block = os.read(source, payload.size + 1 - len(data))
            if not block:
                break
            data.extend(block)
        if _signature(os.fstat(source)) != before:
            _fail('SOURCE_CHANGED')
        if len(data) != payload.size or hashlib.sha256(data).hexdigest() != payload.sha256:
            _fail('LFS_HASH_MISMATCH')
    finally:
        if source is not None:
            os.close(source)
        os.close(parent)
    if not any(marker in data for marker in (b'git-media', b'hawser', b'git-lfs')):
        return
    if job.native.repositories:
        repository = sorted(job.native.repositories)[0]
    else:
        repository = 'lfs-clean-' + secrets.token_hex(8)
        job.native.run('init', {'name': repository, 'bare': False})
    actual = job.native.run('lfs_clean', {'repo': repository, 'path': 'historycrate-payload'}, bytes(data))
    expected = (f'version https://git-lfs.github.com/spec/v1\n'
                f'oid sha256:{payload.sha256}\nsize {payload.size}\n').encode('ascii')
    if actual.stdout != expected or actual.stderr:
        _fail('LFS_CLEAN_ROUNDTRIP_FAILED', 3, sha256=payload.sha256)


def collect_payloads(closure, repositories, job) -> PayloadSet:
    """Verify each required repository cache, keeping one fresh copy per digest."""
    requested = {}
    occurrences = {}
    sizes = {}
    repo_map = {repo.id: repo for repo in repositories}
    if len(repo_map) != len(repositories):
        _fail('DUPLICATE_REPOSITORY', 3)
    for occurrence in closure.lfs:
        _payload_identity(occurrence.sha256, occurrence.size, job)
        if occurrence.repository not in repo_map:
            _fail('MISSING_LFS_REPOSITORY')
        previous = sizes.setdefault(occurrence.sha256, occurrence.size)
        if previous != occurrence.size:
            _fail('LFS_CONFLICTING_SIZE')
        requested[(occurrence.repository, occurrence.sha256)] = occurrence.size
        occurrences.setdefault((occurrence.repository, occurrence.sha256), occurrence)
    if not requested:
        return PayloadSet(())
    _preflight_counter(job, 'unique_lfs_bytes', sum(sizes.values()))
    active_ids = sorted({repo for repo, _ in requested})
    caches = [repo_map[repo].lfs_objects_dir for repo in active_ids]
    # Only declared stores are compared. No alternate cache or remote is searched.
    active_repositories = set(active_ids) | {item.repository for item in closure.commits} | {item.repository for item in closure.objects}
    if not active_repositories <= repo_map.keys():
        _fail('MISSING_LFS_REPOSITORY')
    object_stores = [repo_map[name].git_dir/'objects' for name in sorted(active_repositories)]
    for name in sorted(active_repositories):
        source = repo_map[name].git_dir
        assert_disjoint((job.root, source))
        protected = protected_worktree_root(source)
        if protected is not None:
            assert_disjoint((job.root, protected))
    job.source_paths = tuple(dict.fromkeys((*job.source_paths, *(repo_map[name].git_dir for name in sorted(active_repositories)))))
    job._lfs_source_paths = tuple(dict.fromkeys((*getattr(job, '_lfs_source_paths', ()), *caches)))
    monitor = _Monitor(job)
    try:
        with ExitStack() as stack:
            roots = {}
            for repository in active_ids:
                path = repo_map[repository].lfs_objects_dir
                try:
                    fd = open_directory(path)
                except CrateError as exc:
                    if exc.context.get('errno') == errno.ENOENT:
                        item = next(value for (repo, _), value in occurrences.items() if repo == repository)
                        _fail('LFS_MISSING_PAYLOAD', repository=item.repository, commit=item.commit,
                              path=item.path, sha256=item.sha256)
                    raise
                stack.callback(os.close, fd)
                roots[repository] = (path, fd, _signature(os.fstat(fd)))
            assert_disjoint(tuple(caches + [job.root]))
            for cache in caches:
                for objects in object_stores:
                    assert_disjoint((cache, objects))
            with private_directory(job.root, prefix='lfs-payloads-') as storage:
                monitor.allocation(storage.fd, sum(sizes.values()))
                records = {}
                sources = {}
                seen_files = {}
                for (repository, digest), size in sorted(requested.items()):
                    root_fd = roots[repository][1]
                    try:
                        source, snapshots = _cache_open(root_fd, digest)
                    except FileNotFoundError:
                        item = occurrences[(repository, digest)]
                        _fail('LFS_MISSING_PAYLOAD', repository=repository, commit=item.commit,
                              path=item.path, sha256=digest)
                    try:
                        info = os.fstat(source)
                        identity = (info.st_dev, info.st_ino)
                        if identity in seen_files:
                            _fail('LFS_CACHE_ALIAS', 3)
                        seen_files[identity] = (repository, digest)
                        destination = None
                        try:
                            if digest not in records:
                                destination = os.open(digest, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=storage.fd)
                                os.fchmod(destination, 0o600)
                            _copy_verified(source, destination, digest, size, job, monitor,
                                           'unique_lfs_bytes' if destination is not None else None)
                            if destination is not None:
                                os.fsync(destination)
                                records[digest] = PayloadRecord(digest, size, storage.path/digest)
                        finally:
                            if destination is not None:
                                os.close(destination)
                        _cache_check(root_fd, digest, snapshots)
                        sources[(repository, digest)] = snapshots
                        if not hasattr(job, '_lfs_source_snapshots'): job._lfs_source_snapshots = []
                        job._lfs_source_snapshots.append((repo_map[repository].lfs_objects_dir, digest, size, snapshots))
                    finally:
                        os.close(source)
                for record in records.values():
                    _qualify_clean_roundtrip(record, job)
                for (repository, digest), snapshots in sources.items():
                    _cache_check(roots[repository][1], digest, snapshots)
                for path, fd, expected in roots.values():
                    try:
                        reopened = open_directory(path)
                    except CrateError:
                        _fail('SOURCE_CHANGED')
                    try:
                        if _signature(os.fstat(fd)) != expected or _signature(os.fstat(reopened)) != expected:
                            _fail('SOURCE_CHANGED')
                    finally:
                        os.close(reopened)
                monitor.check()
                result = PayloadSet(tuple(records[key] for key in sorted(records)))
                storage.preserve()
                return result
    except OSError as exc:
        _fail('LFS_SOURCE_IO', 4, errno=exc.errno)


def _existing_target(parent_fd, name):
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    _validate_owned(info, directory=False)
    return _signature(info)


def hydrate_file(parent_fd: int, name: str, mode: int, payload: PayloadRecord, job) -> None:
    """Replace an owned regular pointer with a fresh verified regular file."""
    parts = validate_relative_path(name)
    if len(parts) != 1 or type(mode) is not int or mode not in (0o100644, 0o100755):
        _fail('UNSAFE_LFS_DESTINATION', 3)
    if job.limits.path_depth < 1:
        _fail('BUDGET_EXCEEDED', 5, resource='path_depth')
    if len(name.encode()) > job.limits.component_bytes or len(name.encode()) > job.limits.path_bytes:
        _fail('BUDGET_EXCEEDED', 5, resource='path_bytes')
    _validate_owned(os.fstat(parent_fd), directory=True)
    ancestry = _ancestors(parent_fd)
    for source_path in (*job.source_paths, *getattr(job, '_lfs_source_paths', ())):
        for protected in (Path(source_path), protected_worktree_root(source_path)):
            if protected is None:
                continue
            guard = open_directory(protected)
            try:
                info = os.fstat(guard)
                if (info.st_dev, info.st_ino) in ancestry:
                    _fail('HYDRATION_INSIDE_SOURCE', 3)
            finally:
                os.close(guard)
    _payload_identity(payload.sha256, payload.size, job)
    _preflight_counter(job, 'restore_bytes', payload.size)
    monitor = _Monitor(job)
    temporary = '.historycrate-lfs-' + secrets.token_hex(16)
    destination = None
    source = None
    payload_parent = None
    created = False
    external = not monitor.is_scratch(parent_fd)
    external_before = getattr(job, 'external_materialized_bytes', 0)
    try:
        original = _existing_target(parent_fd, name)
        payload_parent = open_directory(payload.private_path.parent)
        # A PayloadRecord points into this job's owned storage, never arbitrary
        # filesystem content supplied through a manifest or source path.
        root_fd = open_directory(job.root)
        try:
            info = os.fstat(root_fd)
            if (info.st_dev, info.st_ino) not in _ancestors(payload_parent):
                _fail('LFS_PAYLOAD_NOT_PRIVATE', 3)
        finally:
            os.close(root_fd)
        source = open_regular_beneath(payload_parent, payload.private_path.name)
        source_before = _signature(os.fstat(source))
        monitor.allocation(parent_fd, payload.size)
        destination = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                              os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        created = True
        temporary_identity = (os.fstat(destination).st_dev, os.fstat(destination).st_ino)
        _copy_verified(source, destination, payload.sha256, payload.size,
                       job, monitor, 'restore_bytes', external=external)
        os.fchmod(destination, mode & 0o777)
        os.fsync(destination)
        # Re-read the fresh file after applying executable mode. A checksum of
        # only the input stream does not prove the writer's actual output.
        os.lseek(destination, 0, os.SEEK_SET)
        _copy_verified(destination, None, payload.sha256, payload.size, job, monitor)
        if _existing_target(parent_fd, name) != original:
            _fail('SOURCE_CHANGED')
        reopened = open_regular_beneath(payload_parent, payload.private_path.name)
        try:
            if _signature(os.fstat(reopened)) != source_before:
                _fail('SOURCE_CHANGED')
        finally:
            os.close(reopened)
        temporary_info = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
        if _signature(temporary_info) != _signature(os.fstat(destination)):
            _fail('SOURCE_CHANGED')
        _validate_owned(temporary_info, directory=False)
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        created = False
        if external:
            info = os.fstat(parent_fd)
            key = (info.st_dev, info.st_ino, name)
            tracked = getattr(job, '_lfs_external_files', {})
            job.external_materialized_bytes -= tracked.get(key, 0)
            tracked[key] = payload.size
            job._lfs_external_files = tracked
        os.fsync(parent_fd)
        monitor.check()
    except OSError as exc:
        _fail('LFS_HYDRATION_IO', 6, errno=exc.errno)
    finally:
        if destination is not None:
            os.close(destination)
        if source is not None:
            os.close(source)
        if payload_parent is not None:
            os.close(payload_parent)
        if created:
            try:
                remaining = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if (remaining.st_dev, remaining.st_ino) == temporary_identity:
                    os.unlink(temporary, dir_fd=parent_fd)
                    if external:
                        job.external_materialized_bytes = external_before
