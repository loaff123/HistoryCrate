"""Controller-only publication of fully validated, owned scratch trees.

Semantic/native validation is the caller's prerequisite. This module makes fresh
regular-file copies, checks their exact inventory, then uses the audited Linux
no-replace commit primitive. It is change detection for trusted local data, not
an atomic input snapshot, an OS sandbox, or a hard filesystem quota.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import time

from .errors import CrateError
from .monitor import CopyMonitor
from .native import Job
from . import paths

_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class PublicationReport:
    publication: str
    bytes: int
    files: int
    directories: int


@dataclass
class _PublicationReceipt:
    """Commit evidence installed before entering the rename boundary.

    The parent descriptor belongs to publish_tree and remains pinned until the
    receipt is terminal. Once terminal, queries never revisit a pathname or a
    closed/reused descriptor. No source or destination is changed by inspection.
    """
    parent_fd: int | None
    stage_name: str
    destination_name: str
    stage_identity: tuple[int, int]
    state: str = 'armed'

    def reconcile(self):
        if self.state != 'armed':
            return self.state
        try:
            if self.parent_fd is None:
                raise OSError('unsealed publication receipt')
            def entry(name):
                try:
                    return paths._identity(os.stat(name,dir_fd=self.parent_fd,follow_symlinks=False))
                except FileNotFoundError:
                    return None
            target=entry(self.destination_name)
            remaining=entry(self.stage_name)
            # A vanished/replaced stage cannot safely be treated as rollbackable.
            # A matching target is direct evidence of our rename commit, even if
            # an unexpected replacement has appeared at the former stage name.
            if target==self.stage_identity or remaining!=self.stage_identity:
                self.state='published-durability-uncertain'
            else:
                self.state='not-published'
        except BaseException:
            self.state='published-durability-uncertain'
        return self.state


def publication_checkpoint(job):
    """Capture the receipt boundary for one API attempt on a possibly reused Job."""
    return len(getattr(job,'_publication_receipts',()))


def publication_status(job, since=0):
    """Return durable commit evidence since a caller's attempt checkpoint.

    A failure after either published outcome must be reported as exit 6 with
    published-durability-uncertain. Prior successful attempts are excluded by
    ``since``; CLI commands that create one Job can use the default boundary.
    """
    receipts=getattr(job,'_publication_receipts',())
    if type(since) is not int or not 0<=since<=len(receipts):
        raise CrateError('INVALID_PUBLICATION_CHECKPOINT',2)
    outcomes=[receipt.reconcile() for receipt in receipts[since:]]
    if 'published-durability-uncertain' in outcomes:
        return 'published-durability-uncertain'
    return 'published' if 'published' in outcomes else 'not-published'


@dataclass(frozen=True)
class _Entry:
    directory: bool
    mode: int
    size: int
    sha256: str | None
    metadata: tuple[int, ...]

    @property
    def content(self):
        return self.directory, self.mode, self.size, self.sha256


def _fail(code, status=3, **context):
    raise CrateError(code, status, context)


def _metadata(info):
    # Reads may change atime; other identity/metadata changes invalidate a copy.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _owned(info, directory):
    paths._validate_owned(info, directory=directory)
    if info.st_mode & 0o7000:
        _fail('UNSAFE_PERMISSIONS')


def _directory_beneath(root, relative):
    result = os.dup(root)
    try:
        if relative:
            for part in paths.validate_relative_path(relative, repository=False):
                child = os.open(part, paths._DIRECTORY_FLAGS, dir_fd=result)
                os.close(result)
                result = child
                _owned(os.fstat(result), True)
        return result
    except BaseException:
        os.close(result)
        raise


def _inventory(root, job, monitor, maximum):
    """Bounded exact path/type/mode/size/hash inventory with no aliases."""
    result = {}
    seen = set()
    total = 0

    def visit(fd, relative):
        nonlocal total
        before = os.fstat(fd)
        _owned(before, True)
        identity = paths._identity(before)
        if identity in seen:
            _fail('FILESYSTEM_ALIAS')
        seen.add(identity)
        result[relative] = _Entry(True, 0o700 if not relative else stat.S_IMODE(before.st_mode),
                                  0, None, _metadata(before))
        started = time.monotonic()
        names = []
        with os.scandir(fd) as iterator:
            for item in iterator:
                if len(result) + len(names) > job.limits.observation_entries:
                    _fail('BUDGET_EXCEEDED', 5, resource='observation_entries')
                if time.monotonic() - started > 1:
                    _fail('PUBLICATION_INVENTORY_TIMEOUT', 5)
                names.append(item.name)
        for name in sorted(names):
            relative_name = relative + '/' + name if relative else name
            parts = paths.validate_relative_path(relative_name, repository=False)
            if (len(parts) > job.limits.path_depth
                    or len(relative_name.encode('utf-8')) > job.limits.path_bytes
                    or any(len(p.encode('utf-8')) > job.limits.component_bytes for p in parts)):
                _fail('BUDGET_EXCEEDED', 5, resource='path')
            if len(result) > job.limits.observation_entries:
                _fail('BUDGET_EXCEEDED', 5, resource='observation_entries')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            directory = stat.S_ISDIR(info.st_mode)
            _owned(info, directory)
            if directory:
                child = os.open(name, paths._DIRECTORY_FLAGS, dir_fd=fd)
                try:
                    if _metadata(os.fstat(child)) != _metadata(info):
                        _fail('SOURCE_CHANGED', 4)
                    visit(child, relative_name)
                finally:
                    os.close(child)
            else:
                identity = paths._identity(info)
                if identity in seen:
                    _fail('FILESYSTEM_ALIAS')
                seen.add(identity)
                total += info.st_size
                if total > maximum:
                    _fail('BUDGET_EXCEEDED', 5, resource='final_output_bytes',
                          threshold=maximum, observed=total)
                child = paths.open_regular_beneath(fd, name)
                try:
                    if _metadata(os.fstat(child)) != _metadata(info):
                        _fail('SOURCE_CHANGED', 4)
                    digest = hashlib.sha256()
                    count = 0
                    while True:
                        block = os.read(child, min(_CHUNK, info.st_size - count + 1))
                        if not block:
                            break
                        count += len(block)
                        if count > info.st_size:
                            _fail('SOURCE_CHANGED', 4)
                        digest.update(block)
                        monitor.check()
                    if count != info.st_size or _metadata(os.fstat(child)) != _metadata(info):
                        _fail('SOURCE_CHANGED', 4)
                finally:
                    os.close(child)
                result[relative_name] = _Entry(False, stat.S_IMODE(info.st_mode),
                                               count, digest.hexdigest(), _metadata(info))
            if _metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _metadata(info):
                _fail('SOURCE_CHANGED', 4)
        if _metadata(os.fstat(fd)) != _metadata(before):
            _fail('SOURCE_CHANGED', 4)
        monitor.check()

    visit(root, '')
    return result


def _write_all(fd, block):
    view = memoryview(block)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            _fail('PUBLICATION_WRITE_FAILED', 6)
        view = view[written:]


def _copy(source, target, inventory, job, monitor, directory_ids):
    # Keep directories writable during construction; restore their exact modes
    # bottom-up only after all children have been copied.
    directories = sorted((name for name, item in inventory.items() if item.directory),
                         key=lambda name: (name.count('/'), name))
    for name in directories:
        if not name:
            continue
        parent_name, _, leaf = name.rpartition('/')
        parent = _directory_beneath(target, parent_name)
        try:
            os.mkdir(leaf, 0o700, dir_fd=parent)
            directory_ids[name] = paths._identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
        finally:
            os.close(parent)
    for name, entry in sorted(inventory.items()):
        if entry.directory:
            continue
        source_fd = paths.open_regular_beneath(source, name)
        parent_name, _, leaf = name.rpartition('/')
        parent = target_fd = None
        try:
            if _metadata(os.fstat(source_fd)) != entry.metadata:
                _fail('SOURCE_CHANGED', 4)
            parent = _directory_beneath(target, parent_name)
            target_fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            digest = hashlib.sha256()
            count = 0
            while True:
                block = os.read(source_fd, min(_CHUNK, entry.size - count + 1))
                if not block:
                    break
                count += len(block)
                if count > entry.size:
                    _fail('SOURCE_CHANGED', 4)
                monitor.allocation(parent, len(block))
                _write_all(target_fd, block)
                job.external_materialized_bytes += len(block)
                digest.update(block)
                monitor.check()
            if (count != entry.size or digest.hexdigest() != entry.sha256
                    or _metadata(os.fstat(source_fd)) != entry.metadata):
                _fail('SOURCE_CHANGED', 4)
            os.fchmod(target_fd, entry.mode)
        finally:
            for fd in (target_fd, parent, source_fd):
                if fd is not None:
                    os.close(fd)
    for name in reversed(directories):
        directory = _directory_beneath(target, name)
        try:
            os.fchmod(directory, inventory[name].mode)
        finally:
            os.close(directory)
    monitor.check()


def _prepare_rollback(root, directory_ids):
    """Restore cleanup access only on directory inodes this copy created."""
    for name in sorted(directory_ids, key=lambda name: (name.count('/'), name)):
        fd = _directory_beneath(root, name)
        try:
            if paths._identity(os.fstat(fd)) != directory_ids[name]:
                _fail('SOURCE_CHANGED', 4)
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)


def _protected_paths(job):
    yield job.root
    for source in job.source_paths:
        yield Path(source)
        worktree = paths.protected_worktree_root(source)
        if worktree is not None:
            yield worktree
    yield from getattr(job, '_lfs_source_paths', ())
    yield from getattr(job, '_packet_source_paths', ())


def publish_tree(source: Path, destination: Path, job: Job, maximum: int) -> PublicationReport:
    """Publish validated owned scratch; protect work, reporting and own teardown.

    The inner implementation owns the pinned stage/destination evidence. This
    outer boundary also covers exceptions from its cleanup and successful-return
    handoff, so callers need not set a local boolean on the next Python line.
    """
    checkpoint=publication_checkpoint(job)
    state={'old_external':getattr(job,'external_materialized_bytes',0)}
    job.external_materialized_bytes=state['old_external']
    try:
        try:
            result=_publish_tree(source,destination,job,maximum,state)
            return result
        finally:
            _finish_publication(job,state)
    except BaseException as exc:
        if publication_status(job,since=checkpoint)!='not-published' or getattr(exc,'context',{}).get('publication')=='published-durability-uncertain':
            for receipt in getattr(job,'_publication_receipts',())[checkpoint:]:
                if receipt.reconcile()!='not-published':receipt.state='published-durability-uncertain'
            raise CrateError('PUBLISHED_DURABILITY_UNCERTAIN',6,
                             {'publication':'published-durability-uncertain'}) from exc
        if isinstance(exc,CrateError):raise
        if isinstance(exc,KeyboardInterrupt):
            raise CrateError('CANCELLED',130,{'publication':'not-published'}) from exc
        raise CrateError('PUBLICATION_FAILED',6,
                         {'publication':'not-published','errno':getattr(exc,'errno',None)}) from exc


def _publish_tree(source: Path, destination: Path, job: Job, maximum: int, state) -> PublicationReport:
    """Publish a semantically validated tree; all failures include commit status.

    ``maximum`` is the caller's configured packet or restore byte threshold.
    Native calls must have finished, and ``source`` must remain in owned job
    scratch. All source/input paths registered on the Job remain protected.
    Optional job._prepublication_checks are zero-argument read-only callbacks
    invoked after exact copy validation immediately before the atomic helper.
    """
    receipt = None
    parent = source_fd = None
    native_locked = False
    try:
        if type(maximum) is not int or not 0 <= maximum <= max(job.limits.packet_bytes, job.limits.restore_bytes):
            _fail('INVALID_LIMIT', 2, resource='final_output_bytes')
        if job.native.busy:
            _fail('PUBLICATION_NATIVE_ACTIVE', 6, cleanup_uncertain=True)
        if any(record.get('observations', {}).get('cleanup', {}).get('uncertain')
               for record in job.native.records):
            _fail('PUBLICATION_CHILD_EXIT_UNCERTAIN', 6, cleanup_uncertain=True)
        state['native_locked'] = True
        job.native.busy = True
        native_locked = True
        source = paths._absolute(source)
        destination = paths._absolute(destination)
        paths.validate_relative_path(destination.name, repository=False)
        state['parent'] = paths.open_directory(destination.parent)
        parent = state['parent']
        try:
            os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail('DESTINATION_EXISTS', 6)
        for protected in dict.fromkeys(_protected_paths(job)):
            paths.assert_disjoint((Path(protected), destination))
        state['source_fd'] = paths.open_directory(source)
        source_fd = state['source_fd']
        monitor = CopyMonitor(job)
        if not monitor.is_scratch(source_fd):
            _fail('PUBLICATION_SOURCE_NOT_SCRATCH')
        inventory = _inventory(source_fd, job, monitor, maximum)
        total = sum(entry.size for entry in inventory.values())
        monitor.allocation(parent, total)
        paths.check_filesystem_capabilities(destination.parent)
        paths._parent_still_pinned(destination.parent, parent)
        with paths.private_directory(destination.parent, prefix='.historycrate-publish-') as stage:
            directory_ids = {'': paths._identity(os.fstat(stage.fd))}
            try:
                paths._parent_still_pinned(destination.parent, parent)
                _copy(source_fd, stage.fd, inventory, job, monitor, directory_ids)
                if _inventory(source_fd, job, monitor, maximum) != inventory:
                    _fail('SOURCE_CHANGED', 4)
                paths._parent_still_pinned(source, source_fd)
                copied = _inventory(stage.fd, job, monitor, maximum)
                if {name: item.content for name, item in copied.items()} != {name: item.content for name, item in inventory.items()}:
                    _fail('PUBLICATION_COPY_MISMATCH', 4)
                paths._parent_still_pinned(destination.parent, parent)
                monitor.check()
                # Caller-supplied final read-only guards may rehash external
                # sources. NativeAdapter remains locked throughout callbacks.
                for check in tuple(getattr(job, '_prepublication_checks', ())):
                    check()
                receipt = _PublicationReceipt(parent,stage.path.name,destination.name,
                                              directory_ids[''])
                state['receipt'] = receipt
                if not hasattr(job,'_publication_receipts'):
                    job._publication_receipts=[]
                job._publication_receipts.append(receipt)
                paths.atomic_publish(stage.path, destination)
                receipt.state = 'published'
                # No cleanup or reporting failure after this point may remove output.
                stage.preserve()
            except BaseException as exc:
                if receipt is not None and isinstance(exc, CrateError) and exc.context.get('publication') == 'published-durability-uncertain':
                    receipt.state = 'published-durability-uncertain'
                uncertain = receipt is not None and receipt.reconcile() != 'not-published'
                if uncertain:
                    receipt.state = 'published-durability-uncertain'
                    stage.preserve()
                if not uncertain:
                    try:
                        _prepare_rollback(stage.fd, directory_ids)
                    except BaseException as cleanup_error:
                        stage.preserve()
                        raise CrateError('PUBLICATION_CLEANUP_FAILED', 6,
                                         {'cleanup_uncertain': True}) from cleanup_error
                raise
        report = PublicationReport('published', total,
                                   sum(not item.directory for item in inventory.values()),
                                   sum(item.directory for item in inventory.values()))
        return report
    except BaseException as exc:
        uncertain = ((receipt is not None and receipt.reconcile() != 'not-published')
                     or (isinstance(exc, CrateError) and
                         exc.context.get('publication') == 'published-durability-uncertain'))
        if uncertain:
            if receipt is not None:receipt.state='published-durability-uncertain'
            raise CrateError('PUBLISHED_DURABILITY_UNCERTAIN', 6,
                             {'publication': 'published-durability-uncertain'}) from exc
        if isinstance(exc, CrateError):
            raise CrateError(exc.code, exc.exit_code,
                             dict(exc.context, publication='not-published')) from exc
        if isinstance(exc, KeyboardInterrupt):
            raise CrateError('CANCELLED', 130, {'publication': 'not-published'}) from exc
        raise CrateError('PUBLICATION_FAILED', 6,
                         {'publication': 'not-published', 'errno': getattr(exc, 'errno', None)}) from exc


def _finish_publication(job, state):
    old_external=state['old_external']
    native_locked=state.get('native_locked',False)
    receipt=state.get('receipt')
    source_fd=state.get('source_fd')
    parent=state.get('parent')
    job.external_materialized_bytes = old_external
    if native_locked:
        job.native.busy = False
    # Seal before descriptor teardown. A later caller interruption reads
    # terminal evidence instead of relying on its next Python assignment.
    if receipt is not None:
        receipt.reconcile()
        receipt.parent_fd=None
    close_failure = None
    for fd in (source_fd, parent):
        if fd is not None:
            try:
                os.close(fd)
            except BaseException as exc:
                close_failure = exc
    if close_failure is not None:
        if receipt is not None and receipt.reconcile() != 'not-published':
            receipt.state='published-durability-uncertain'
            raise CrateError('PUBLISHED_DURABILITY_UNCERTAIN', 6,
                             {'publication': 'published-durability-uncertain'}) from close_failure
        raise CrateError('PUBLICATION_FAILED', 6,
                         {'publication': 'not-published', 'errno': getattr(close_failure,'errno',None)}) from close_failure
