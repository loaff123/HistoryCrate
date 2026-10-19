"""Canonical, bounded Git object access from controlled staging only."""
from __future__ import annotations

import io
import re
import sys
import time
from collections import OrderedDict
from dataclasses import fields, is_dataclass
from typing import BinaryIO

from .errors import CrateError
from .model import AcquiredRepo, CommitRecord, ObjectRecord, TreeEntry
from .native import Job, _oid
from .monitor import CopyMonitor


def _fail(code, **context):
    raise CrateError(code, 4, context)


def parse_commit(repository: str, oid: str, data: bytes) -> CommitRecord:
    headers, separator, _message = data.partition(b'\n\n')
    if not separator or b'\0' in headers: _fail('INVALID_COMMIT', oid=oid)
    lines = headers.split(b'\n')
    match = re.fullmatch(rb'tree ([0-9a-f]{40})', lines[0])
    if not match: _fail('INVALID_COMMIT', oid=oid)
    tree = match[1].decode()
    parents = []
    previous = b'tree'
    structural_seen = {b'tree'}
    parents_done = False
    for line in lines[1:]:
        if line.startswith(b' '):
            if previous in (b'tree', b'parent', b'author', b'committer'): _fail('INVALID_COMMIT', oid=oid)
            continue
        key, space, value = line.partition(b' ')
        if not space or not re.fullmatch(rb'[A-Za-z][A-Za-z0-9-]*', key): _fail('INVALID_COMMIT', oid=oid)
        previous = key
        if key == b'parent':
            if parents_done or not re.fullmatch(rb'[0-9a-f]{40}', value): _fail('INVALID_COMMIT', oid=oid)
            parents.append(value.decode())
        else:
            parents_done = True
            if key in (b'tree', b'author', b'committer'):
                if key in structural_seen: _fail('INVALID_COMMIT', oid=oid)
                structural_seen.add(key)
    if not {b'author', b'committer'} <= structural_seen: _fail('INVALID_COMMIT', oid=oid)
    return CommitRecord(repository, oid, tree, tuple(parents))


def parse_tree(data: bytes, *, maximum_entries: int = 5_000_000, checkpoint=None) -> tuple[TreeEntry, ...]:
    if type(maximum_entries) is not int or not 0 <= maximum_entries <= 5_000_000:
        raise CrateError('INVALID_LIMIT', 2, {'resource': 'commit_path_visits'})
    if checkpoint is not None and not callable(checkpoint):
        raise CrateError('INVALID_PARSER_CHECKPOINT', 2)
    result = []
    offset = 0
    seen = set()
    previous = None
    while offset < len(data):
        if len(result) >= maximum_entries:
            raise CrateError('BUDGET_EXCEEDED', 5, {'resource': 'commit_path_visits', 'threshold': maximum_entries})
        if checkpoint is not None and len(result) % 1024 == 0:
            checkpoint()
        space = data.find(b' ', offset)
        nul = data.find(b'\0', space + 1) if space >= 0 else -1
        if space < 0 or nul < 0 or len(data) - nul - 1 < 20: _fail('INVALID_TREE')
        mode_data = data[offset:space]
        if mode_data not in (b'40000', b'100644', b'100755', b'120000', b'160000'): _fail('INVALID_TREE_MODE')
        mode = int(mode_data, 8)
        name = data[space + 1:nul]
        if not name or b'/' in name or name in (b'.', b'..') or name in seen: _fail('INVALID_TREE_NAME')
        sort_key = name + (b'/' if mode == 0o40000 else b'\0')
        if previous is not None and sort_key <= previous: _fail('INVALID_TREE_ORDER')
        previous = sort_key
        seen.add(name)
        result.append(TreeEntry(mode, name, data[nul + 1:nul + 21].hex()))
        offset = nul + 21
    return tuple(result)


class _Discard:
    def write(self, data):
        return len(data)


class _ParsedCache:
    """Phase-local LRU of verified immutable records, never raw object bytes.

    Admission charges retained Python values (shared references conservatively
    charged again) plus 512 bytes per entry for mapping/bookkeeping overhead.
    This is a cache accounting bound, not an RSS/allocator containment claim.
    """
    def __init__(self):
        self.entries = OrderedDict()
        self.used_bytes = 0

    def _bounds(self, limits):
        return (min(limits.observation_entries, limits.git_objects, limits.commits),
                min(limits.captured_bytes, limits.observed_rss_bytes // 16))

    def _evict(self):
        _, (_, size) = self.entries.popitem(last=False)
        self.used_bytes -= size

    def get(self, key, limits):
        count, size = self._bounds(limits)
        while self.entries and (len(self.entries) > count or self.used_bytes > size):
            self._evict()
        entry = self.entries.get(key)
        if entry is None:
            return None
        self.entries.move_to_end(key)
        return entry[0]

    def put(self, key, record, parsed, limits, checkpoint):
        count, maximum = self._bounds(limits)
        if not count or record.size > maximum:
            return
        value = (record, parsed)
        # An iterator stack bounds traversal memory, including for large trees.
        pending = [iter((key, value))]
        size, visited = 512, 0
        while pending:
            try:
                item = next(pending[-1])
            except StopIteration:
                pending.pop()
                continue
            size += sys.getsizeof(item)
            if size > maximum:
                return
            visited += 1
            if visited % 1024 == 0:
                checkpoint()
            if isinstance(item, tuple):
                pending.append(iter(item))
            elif is_dataclass(item):
                pending.append(iter(tuple(getattr(item, field.name) for field in fields(item))))
        previous = self.entries.pop(key, None)
        if previous is not None:
            self.used_bytes -= previous[1]
        while self.entries and (len(self.entries) >= count or self.used_bytes + size > maximum):
            self._evict()
        self.entries[key] = (value, size)
        self.used_bytes += size


class ObjectReader:
    def __init__(self, acquired: AcquiredRepo, job: Job):
        self.acquired = acquired
        self.job = job
        self.repository = acquired.id
        self.records: dict[str, ObjectRecord] = {}
        self._parser_monitor = None
        self._last_cache_check = 0
        if not hasattr(job, '_parsed_object_cache'):
            job._parsed_object_cache = _ParsedCache()
        if job.native._repo(acquired.id) != acquired.stage_git_dir:
            _fail('STAGING_CHANGED', repository=acquired.id)

    def _account(self, oid):
        _oid(oid)
        if not hasattr(self.job.budget, '_accounted_git_objects'): self.job.budget._accounted_git_objects = set()
        identity = (self.repository, oid)
        if identity not in self.job.budget._accounted_git_objects:
            self.job.budget.charge('git_objects', 1)
            self.job.budget._accounted_git_objects.add(identity)

    def _remember(self, record):
        previous = self.records.get(record.oid)
        if previous is not None and previous != record:
            _fail('OBJECT_CHANGED', repository=self.repository, oid=record.oid)
        self.records[record.oid] = record

    def _cache_checkpoint(self):
        now = time.monotonic()
        if now - self.job.native.started > self.job.limits.job_wall_seconds:
            raise CrateError('BUDGET_EXCEEDED', 5, {'resource': 'job_wall_seconds'})
        if now - self._last_cache_check >= 1:
            if self._parser_monitor is None:
                self._parser_monitor = CopyMonitor(self.job)
            self._parser_monitor.check()
            self._last_cache_check = now

    def _cached(self, oid, interpretation):
        self._account(oid)
        if self.job.native._repo(self.repository) != self.acquired.stage_git_dir:
            _fail('STAGING_CHANGED', repository=self.repository)
        cached = self.job._parsed_object_cache.get((self.repository, oid, interpretation), self.job.limits)
        if cached is not None:
            self._cache_checkpoint()
            record, parsed = cached
            if record.size > self.job.limits.git_object_bytes:
                raise CrateError('BUDGET_EXCEEDED', 5, {'resource': 'git_object_bytes'})
            self._remember(record)
            return parsed
        return None

    def _cache(self, oid, interpretation, parsed):
        self.job._parsed_object_cache.put((self.repository, oid, interpretation), self.records[oid],
                                         parsed, self.job.limits, self._cache_checkpoint)

    def _stream(self, oid, sink, missing='MISSING_OBJECT', expected=None):
        self._account(oid)
        try:
            kind, size = self.job.native.stream_object(self.repository, oid, sink)
        except CrateError as exc:
            if exc.code == 'MISSING_OBJECT':
                _fail(missing, repository=self.repository, oid=oid)
            raise
        if expected is not None and kind != expected:
            _fail('OBJECT_TYPE_MISMATCH', repository=self.repository, oid=oid, expected=expected, actual=kind)
        record = ObjectRecord(self.repository, oid, kind, size)
        self._remember(record)
        return record

    def read(self, oid: str) -> tuple[str, bytes]:
        sink = io.BytesIO()
        record = self._stream(oid, sink)
        return record.kind, sink.getvalue()

    def info(self, oid: str) -> ObjectRecord:
        # Controlled acquired object stores remain immutable for this Job.
        # Cache verified metadata only; read/copy still verify their actual bytes.
        self._account(oid)
        if oid in self.records: return self.records[oid]
        return self._stream(oid, _Discard())

    def commit(self, oid: str) -> CommitRecord:
        cached = self._cached(oid, 'commit')
        if cached is not None:
            return cached
        sink = io.BytesIO()
        self._stream(oid, sink, 'MISSING_COMMIT', 'commit')
        result = parse_commit(self.repository, oid, sink.getvalue())
        self._cache(oid, 'commit', result)
        return result

    def tree(self, oid: str) -> tuple[TreeEntry, ...]:
        cached = self._cached(oid, 'tree')
        if cached is not None:
            if len(cached) > self.job.limits.commit_path_visits:
                raise CrateError('BUDGET_EXCEEDED', 5, {'resource': 'commit_path_visits',
                                                     'threshold': self.job.limits.commit_path_visits})
            return cached
        sink = io.BytesIO()
        self._stream(oid, sink, 'MISSING_TREE', 'tree')
        if self._parser_monitor is None:
            self._parser_monitor = CopyMonitor(self.job)
        result = parse_tree(sink.getvalue(), maximum_entries=self.job.limits.commit_path_visits,
                            checkpoint=self._parser_monitor.check)
        self._cache(oid, 'tree', result)
        return result

    def copy_blob(self, oid: str, sink: BinaryIO) -> ObjectRecord:
        return self._stream(oid, sink, 'MISSING_BLOB', 'blob')
