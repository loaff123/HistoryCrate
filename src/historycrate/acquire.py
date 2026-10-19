"""Read-only, descriptor-pinned acquisition of trusted local Git object stores.

This is a change-detecting read, not a filesystem snapshot or hostile-input sandbox.
No native command executes in a source directory or activates source configuration.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from .errors import CrateError
from .model import AcquiredRepo, RepoSpec, Spec
from .native import Job, _name
from .monitor import CopyMonitor
from .paths import (_DIRECTORY_FLAGS, _validate_owned, assert_disjoint,
                    open_directory, open_regular_beneath, protected_worktree_root)

_HEX2 = re.compile(r'[0-9a-f]{2}\Z')
_HEX38 = re.compile(r'[0-9a-f]{38}\Z')
_PACK = re.compile(r'pack-([0-9a-f]{40})\.(pack|idx|rev|bitmap|keep|mtimes)\Z')
_ROOT_MARKERS = {'shallow', 'commondir', 'worktrees', 'reftable'}
_INFO_AUX = {'packs', 'commit-graph', 'commit-graphs'}
_PACK_AUX = {'multi-pack-index'}
_STRUCTURAL = {'core.repositoryformatversion', 'core.bare', 'core.worktree', 'core.objectformat'}


def _fail(code, status=3, **context):
    raise CrateError(code, status, context)


def _metadata(info):
    # atime can legitimately change when source files are read.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _inventory(root_fd, job):
    """Inventory only admitted source metadata/stores; never discover submodules."""
    result = {'': _metadata(os.fstat(root_fd))}
    count = 0
    started = time.monotonic()

    def walk(fd, relative, role):
        nonlocal count
        before = _metadata(os.fstat(fd))
        with os.scandir(fd) as entries:
            names = []
            for entry in entries:
                count += 1
                if count > job.limits.observation_entries:
                    _fail('BUDGET_EXCEEDED', 5, resource='observation_entries')
                if time.monotonic() - started > 1:
                    _fail('SOURCE_INVENTORY_TIMEOUT', 5)
                names.append(entry.name)
        for name in sorted(names):
            path = relative + '/' + name if relative else name
            if (role == 'root' and name in _ROOT_MARKERS
                    or path in ('info/grafts', 'objects/info/alternates', 'objects/info/http-alternates', 'refs/replace')
                    or name.endswith('.promisor') and relative == 'objects/pack'):
                _fail('UNSUPPORTED_REPOSITORY', marker=path)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            directory = stat.S_ISDIR(info.st_mode)
            _validate_owned(info, directory=directory)
            result[path] = _metadata(info)
            child_role = None
            if role == 'root':
                if name in ('objects', 'refs', 'info'):
                    if not directory: _fail('INVALID_REPOSITORY_LAYOUT', 4)
                    child_role = name
            elif role == 'objects':
                if not directory: _fail('INVALID_OBJECT_PATH', 4)
                if _HEX2.fullmatch(name): child_role = 'fanout'
                elif name == 'pack': child_role = 'pack'
                elif name == 'info': child_role = 'object-info'
                else: _fail('INVALID_OBJECT_PATH', 4)
            elif role == 'fanout':
                if directory or not _HEX38.fullmatch(name): _fail('INVALID_OBJECT_PATH', 4)
            elif role == 'pack':
                if directory or not (_PACK.fullmatch(name) or name in _PACK_AUX
                                     or re.fullmatch(r'multi-pack-index-[0-9a-f]{40}\.(bitmap|rev)', name)):
                    _fail('INVALID_PACK_PATH', 4)
            elif role == 'object-info':
                if name not in _INFO_AUX: _fail('INVALID_OBJECT_AUXILIARY', 4)
                if directory:
                    if name != 'commit-graphs': _fail('INVALID_OBJECT_AUXILIARY', 4)
                    child_role = 'commit-graphs'
            elif role == 'commit-graphs':
                if directory or not (name == 'commit-graph-chain' or re.fullmatch(r'graph-[0-9a-f]{40}\.graph', name)):
                    _fail('INVALID_OBJECT_AUXILIARY', 4)
            elif role == 'refs':
                if directory: child_role = 'refs'
            # info/exclude and source hooks/logs/index are never read or copied.
            if child_role:
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=fd)
                try:
                    if _metadata(os.fstat(child)) != _metadata(info): _fail('SOURCE_CHANGED', 4)
                    walk(child, path, child_role)
                    if _metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _metadata(info):
                        _fail('SOURCE_CHANGED', 4)
                finally:
                    os.close(child)
        if _metadata(os.fstat(fd)) != before: _fail('SOURCE_CHANGED', 4)

    walk(root_fd, '', 'root')
    if 'config' not in result or 'objects' not in result:
        _fail('INVALID_REPOSITORY_LAYOUT', 4)
    return result


def _copy_file(root_fd, relative, expected, destination, maximum, monitor):
    """Copy one pinned regular file, checking metadata and exact byte count."""
    try:
        source = open_regular_beneath(root_fd, relative)
    except (OSError, CrateError):
        _fail('SOURCE_CHANGED', 4, path=relative)
    digest = hashlib.sha256()
    size = 0
    try:
        if _metadata(os.fstat(source)) != expected: _fail('SOURCE_CHANGED', 4, path=relative)
        if expected[5] > maximum: _fail('BUDGET_EXCEEDED', 5, resource='source_file_bytes')
        destination.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
        with destination.open('xb') as output:
            os.chmod(destination, 0o600)
            while True:
                monitor.check()
                block = os.read(source, min(1024 * 1024, maximum - size + 1))
                if not block: break
                size += len(block)
                if size > maximum: _fail('SOURCE_CHANGED', 4, path=relative)
                digest.update(block)
                if output.write(block) != len(block): _fail('COPY_FAILED', 6)
                output.flush()
                monitor.check()
        if size != expected[5] or _metadata(os.fstat(source)) != expected:
            _fail('SOURCE_CHANGED', 4, path=relative)
        # A renamed entry may leave the opened inode unchanged.
        check = open_regular_beneath(root_fd, relative)
        try:
            if _metadata(os.fstat(check)) != expected: _fail('SOURCE_CHANGED', 4, path=relative)
        finally:
            os.close(check)
    finally:
        os.close(source)
    return digest.hexdigest()


def _validate_config(raw, repo):
    if raw and not raw.endswith(b'\0'): _fail('INVALID_SOURCE_CONFIG', 4)
    seen = {}
    for item in raw.split(b'\0')[:-1]:
        key, separator, value = item.partition(b'\n')
        try:
            key = key.decode('utf-8').lower()
        except UnicodeError:
            _fail('INVALID_SOURCE_CONFIG', 4)
        if (key.startswith(('include.', 'includeif.', 'extensions.', 'lfs.extension.', 'lfs.customtransfer.'))
                or key.startswith('remote.') and key.rsplit('.', 1)[-1] in ('promisor', 'partialclonefilter')
                or key in ('core.partialclone', 'core.partialclonefilter', 'lfs.standalonetransferagent')):
            _fail('UNSUPPORTED_REPOSITORY', setting=key)
        if key in _STRUCTURAL:
            if key in seen or not separator: _fail('UNSUPPORTED_REPOSITORY', setting=key)
            seen[key] = value
    if seen.get('core.repositoryformatversion') != b'0':
        _fail('UNSUPPORTED_REPOSITORY', setting='repositoryformatversion')
    if 'core.objectformat' in seen and seen['core.objectformat'].lower() != b'sha1':
        _fail('UNSUPPORTED_REPOSITORY', setting='objectformat')
    bare = seen.get('core.bare', b'false').lower()
    if bare not in (b'true', b'false', b'yes', b'no', b'1', b'0', b'on', b'off'):
        _fail('UNSUPPORTED_REPOSITORY', setting='bare')
    if bare not in (b'true', b'yes', b'1', b'on'):
        parts = repo.git_dir.parts
        standard = repo.git_dir.name == '.git' or any(parts[i:i + 2] == ('.git', 'modules') for i in range(len(parts) - 2))
        if not standard: _fail('UNSUPPORTED_REPOSITORY', setting='nonstandard_nonbare_layout')


def _validate_packed_refs(data):
    for line in data.splitlines():
        if not line or line.startswith(b'#'): continue
        if line.startswith(b'^'):
            if not re.fullmatch(rb'\^[0-9a-f]{40}', line): _fail('INVALID_SOURCE_REFS', 4)
            continue
        match = re.fullmatch(rb'([0-9a-f]{40}) (refs/[^\x00-\x20\x7f]+)', line)
        if not match: _fail('INVALID_SOURCE_REFS', 4)
        if match[2] == b'refs/replace' or match[2].startswith(b'refs/replace/'):
            _fail('UNSUPPORTED_REPOSITORY', marker='packed replacement ref')


def _verify_inventory(repo, root_fd, before, job):
    try:
        reopened = open_directory(repo.git_dir)
        try:
            if _metadata(os.fstat(reopened)) != before['']: _fail('SOURCE_CHANGED', 4)
        finally:
            os.close(reopened)
        if _inventory(root_fd, job) != before: _fail('SOURCE_CHANGED', 4)
    except (OSError, CrateError) as exc:
        if isinstance(exc, CrateError) and exc.exit_code == 5: raise
        _fail('SOURCE_CHANGED', 4)


def acquire_repository(repo: RepoSpec, job: Job) -> AcquiredRepo:
    """Acquire one explicit concrete store; source refs are never installed."""
    if not isinstance(repo, RepoSpec): _fail('INVALID_REPOSITORY_SPEC', 2)
    _name(repo.id)
    for path in (repo.git_dir, repo.lfs_objects_dir):
        if not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts:
            _fail('INVALID_REPOSITORY_PATH', 2)
    if repo.id in job.native.repositories: _fail('DUPLICATE_REPOSITORY_ID', 2)
    # The caller may construct a Job without source_paths; recheck disjointness.
    protected = protected_worktree_root(repo.git_dir)
    assert_disjoint((job.root, protected or repo.git_dir))
    assert_disjoint((job.root, repo.git_dir))
    root_fd = open_directory(repo.git_dir)
    try:
        for source in dict.fromkeys((repo.git_dir, protected or repo.git_dir)):
            guard_fd = open_directory(source)
            try:
                info = os.fstat(guard_fd)
                source_identity = (info.st_dev, info.st_ino)
                for tool in (job.tools.git, job.tools.git_lfs, job.tools.git_exec_path):
                    if source == tool or source in tool.parents:
                        _fail('SOURCE_PATH_CANNOT_BE_TOOL')
                    for ancestor in (tool, *tool.parents):
                        try:
                            tool_info = ancestor.stat(follow_symlinks=False)
                        except FileNotFoundError:
                            continue  # The adapter separately validates executable identity.
                        if source_identity == (tool_info.st_dev, tool_info.st_ino):
                            _fail('SOURCE_PATH_CANNOT_BE_TOOL')
            finally:
                os.close(guard_fd)
        before = _inventory(root_fd, job)
        objects = [name for name in before if re.fullmatch(r'objects/[0-9a-f]{2}/[0-9a-f]{38}', name)
                   or re.fullmatch(r'objects/pack/pack-[0-9a-f]{40}\.pack', name)]
        admitted = ['config'] + (['packed-refs'] if 'packed-refs' in before else []) + objects
        total = sum(before[name][5] for name in admitted)
        job.budget.charge('source_git_bytes', total)
        monitor = CopyMonitor(job)
        destination_fd = open_directory(job.root)
        try:
            monitor.allocation(destination_fd, total)
        finally:
            os.close(destination_fd)
        inert_name = 'source-' + hashlib.sha256(repo.id.encode()).hexdigest()[:24]
        inert = job.root / inert_name
        copied = {'config': _copy_file(root_fd, 'config', before['config'], inert, job.limits.config_bytes, monitor)}
        try:
            parsed = job.native.run('parse_config', {'name': inert_name})
            if parsed.stderr: _fail('INVALID_SOURCE_CONFIG', 4)
            _validate_config(parsed.stdout, repo)
        finally:
            inert.unlink()
        if 'packed-refs' in before:
            refs = job.root / (inert_name + '-refs')
            copied['packed-refs'] = _copy_file(root_fd, 'packed-refs', before['packed-refs'], refs, job.limits.config_bytes, monitor)
            _validate_packed_refs(refs.read_bytes())
        # Detect mutations during metadata reads before creating a repository.
        _verify_inventory(repo, root_fd, before, job)
        job.native.run('init', {'name': repo.id, 'bare': True})
        stage = job.native._repo(repo.id)
        for relative in objects:
            copied[relative] = _copy_file(root_fd, relative, before[relative], stage / relative,
                                          job.limits.source_git_bytes, monitor)
        _verify_inventory(repo, root_fd, before, job)
        for relative in objects:
            if relative.endswith('.pack'):
                job.native.run('rebuild_pack', {'repo': repo.id, 'pack': Path(relative).stem[5:]})
        job.native.run('fsck_acquired', {'repo': repo.id})
        listed = job.native.run('list_objects', {'repo': repo.id})
        roots = []
        seen_objects = set()
        acquired_count = getattr(job, 'acquired_git_object_count', 0)
        for line in listed.stdout.splitlines():
            match = re.fullmatch(rb'([0-9a-f]{40}) (blob|tree|commit|tag) (0|[1-9][0-9]*)', line)
            if not match: _fail('INVALID_OBJECT_INVENTORY', 4)
            oid = match[1].decode()
            if oid in seen_objects: _fail('INVALID_OBJECT_INVENTORY', 4)
            if acquired_count + len(seen_objects) >= job.limits.git_objects:
                _fail('BUDGET_EXCEEDED', 5, resource='git_objects', phase='acquisition', threshold=job.limits.git_objects)
            seen_objects.add(oid)
            if int(match[3]) > job.limits.git_object_bytes:
                _fail('BUDGET_EXCEEDED', 5, resource='git_object_bytes')
            if match[2] != b'blob': roots.append(oid)
        job.acquired_git_object_count = acquired_count + len(seen_objects)
        # With no refs, Git's ordinary fsck does not traverse dangling graphs.
        # Supply every nonblob object as an explicit root, in bounded batches.
        # These are controlled staged OIDs, never copied source refs.
        for start in range(0, len(roots), 512):
            job.native.run('fsck_roots', {'repo': repo.id, 'oids': tuple(roots[start:start + 512])})
        _verify_inventory(repo, root_fd, before, job)
        # Include stat inventory and copied content hashes; atime is excluded.
        encoded = json.dumps({'entries': before, 'hashes': copied}, sort_keys=True, separators=(',', ':')).encode()
        # Later descriptor-relative writers must guard every acquired source,
        # including callers that constructed Job with the default empty list.
        job.source_paths = tuple(dict.fromkeys((*job.source_paths, repo.git_dir)))
        if not hasattr(job, '_source_snapshots'): job._source_snapshots = []
        job._source_snapshots.append((repo, before, copied))
        return AcquiredRepo(repo.id, stage, hashlib.sha256(encoded).hexdigest())
    except OSError as exc:
        if exc.errno in (errno.ENOSPC, errno.EDQUOT): _fail('INSUFFICIENT_SPACE', 5, errno=exc.errno)
        if exc.errno in (errno.ENOENT, errno.ESTALE): _fail('SOURCE_CHANGED', 4, errno=exc.errno)
        _fail('SOURCE_READ_FAILED', 4, errno=exc.errno)
    finally:
        os.close(root_fd)


class RepositoryPool:
    """Lazy repository identity cache; no missing-store or remote discovery."""
    def __init__(self, spec: Spec, job: Job):
        self.spec = spec
        self.job = job
        self.repositories = {repo.id: repo for repo in spec.repositories}
        if len(self.repositories) != len(spec.repositories): _fail('DUPLICATE_REPOSITORY_ID', 2)
        self.acquired = {}
        self._identities = set()
        self._stores = []

    def get(self, repository_id: str) -> AcquiredRepo:
        if repository_id in self.acquired: return self.acquired[repository_id]
        if repository_id not in self.repositories: _fail('UNKNOWN_REPOSITORY', 2, repository=repository_id)
        repo = self.repositories[repository_id]
        fd = open_directory(repo.git_dir)
        try:
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
        if identity in self._identities: _fail('DUPLICATE_REPOSITORY_IDENTITY')
        stores = [repo.git_dir / 'objects']
        # Missing default caches are admissible until a payload is demanded.
        # Check actual endpoints with no-follow opens; do not silently skip links.
        if repo.lfs_objects_dir.exists() or repo.lfs_objects_dir.is_symlink():
            stores.append(repo.lfs_objects_dir)
        assert_disjoint(tuple(self._stores + stores))
        self.job.budget.charge('repositories', 1)
        acquired = acquire_repository(repo, self.job)
        self._identities.add(identity)
        self._stores.extend(stores)
        self.acquired[repository_id] = acquired
        return acquired


def recheck_sources(job):
    """Rehash admitted original source bytes at the final prepublication gate."""
    monitor = CopyMonitor(job)
    for repo, before, copied in getattr(job, '_source_snapshots', ()):
        root = open_directory(repo.git_dir)
        try:
            _verify_inventory(repo, root, before, job)
            for relative, expected_hash in copied.items():
                source = open_regular_beneath(root, relative)
                try:
                    if _metadata(os.fstat(source)) != before[relative]: _fail('SOURCE_CHANGED', 4)
                    digest = hashlib.sha256(); size = 0
                    while True:
                        block = os.read(source, 1024 * 1024)
                        if not block: break
                        size += len(block); digest.update(block); monitor.check()
                        if size > before[relative][5]: _fail('SOURCE_CHANGED', 4)
                    if size != before[relative][5] or digest.hexdigest() != expected_hash or _metadata(os.fstat(source)) != before[relative]:
                        _fail('SOURCE_CHANGED', 4)
                finally: os.close(source)
            _verify_inventory(repo, root, before, job)
        finally: os.close(root)
    for path, digest, size, expected in getattr(job, '_lfs_source_snapshots', ()):
        root = open_directory(path)
        try:
            from .lfs import _cache_open, _cache_check
            source, snapshots = _cache_open(root, digest)
            try:
                if snapshots != expected: _fail('SOURCE_CHANGED', 4)
                result = hashlib.sha256(); actual = 0
                while True:
                    block = os.read(source, 1024 * 1024)
                    if not block: break
                    actual += len(block); result.update(block); monitor.check()
                    if actual > size: _fail('SOURCE_CHANGED', 4)
                if actual != size or result.hexdigest() != digest: _fail('SOURCE_CHANGED', 4)
                _cache_check(root, digest, expected)
            finally: os.close(source)
        finally: os.close(root)
