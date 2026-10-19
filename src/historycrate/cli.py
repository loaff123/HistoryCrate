"""Fail-closed trusted-local command orchestration; no source-native operations."""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time

from .acquire import RepositoryPool, _metadata, recheck_sources
from .closure import build_closure, explain_inclusion
from .errors import CrateError
from .lfs import collect_payloads
from .limits import Budget, Limits
from .manifest import value
from .model import AcquiredRepo
from .native import Job, doctor, qualify_toolchain, _name, _oid, _path
from .objects import ObjectReader
from .packet import create_packet, verify_packet, validate_selection_output, _phase, _copy, _preflight_native
from .paths import (_absolute, _ancestors, _open_absolute_directory, open_directory, open_regular_beneath,
                    protected_worktree_root)
from .publication import publication_status
from .reports import (INSPECT_CHECKS, PACKET_CHECKS, base_report, observe,
                      remediation, selection_warnings)
from .restore import restore_verified
from .schema import load_spec

_DISCLOSURE = ('Trusted-local-v1 only. No OS sandbox, network containment, or hard aggregate '
               'resource quota. Use only trusted local data with concurrent writers stopped.')


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['allow_abbrev'] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise CrateError('INVALID_INVOCATION', 2, {'detail': message})


def _parser():
    parser = Parser(prog='historycrate', description=_DISCLOSURE)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('doctor', 'inspect', 'pack', 'verify', 'restore', 'explain'):
        sub = commands.add_parser(name, description=_DISCLOSURE)
        sub.add_argument('--git', required=True, type=Path, metavar='ABSOLUTE_PATH')
        sub.add_argument('--git-lfs', required=True, type=Path, metavar='ABSOLUTE_PATH')
        sub.add_argument('--limit', action='append', default=[], metavar='NAME=INTEGER',
                         help='Lower a profile resource cap; repeat for distinct resources.')
        if name == 'doctor':
            continue
        sub.add_argument('--trust-local-data', action='store_true', required=True,
                         help='Acknowledge trusted local inputs; this is not authenticity or containment.')
        if name in ('inspect', 'pack'):
            sub.add_argument('--spec', required=True, type=Path)
        else:
            sub.add_argument('--packet', required=True, type=Path)
        if name in ('pack', 'restore'):
            sub.add_argument('--out', required=True, type=Path)
        if name == 'verify':
            sub.add_argument('--rehearse', nargs=2, metavar=('ROOT_ID', 'COMMIT'))
        if name == 'restore':
            sub.add_argument('--root', required=True)
            sub.add_argument('--commit', required=True)
        if name == 'explain':
            sub.add_argument('--repo', required=True)
            sub.add_argument('--commit', required=True)
            sub.add_argument('--path')
    return parser


def _overrides(items):
    result = {}
    for item in items:
        match = re.fullmatch(r'([a-z_]+)=([0-9]{1,20})', item)
        if match is None or match[1] in result:
            raise CrateError('INVALID_LIMIT', 2, {'reason': 'expected distinct NAME=nonnegative_integer caps'})
        result[match[1]] = int(match[2])
    Limits().lower(result)
    return result


def _spec_bytes(path, limits):
    """Bound bytes before JSON parsing and pin every path component no-follow."""
    path = _absolute(path)
    parent = open_directory(path.parent)
    source = None
    try:
        directory = os.fstat(parent)
        parent_identity = directory.st_dev, directory.st_ino
        source = open_regular_beneath(parent, path.name)
        before = _metadata(os.fstat(source))
        if os.fstat(source).st_size > limits.spec_bytes:
            raise CrateError('BUDGET_EXCEEDED', 5, {'resource': 'spec_bytes', 'threshold': limits.spec_bytes})
        data = bytearray()
        while len(data) <= limits.spec_bytes:
            block = os.read(source, min(65536, limits.spec_bytes + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        Budget(limits).charge('spec_bytes', len(data))
        if _metadata(os.fstat(source)) != before or len(data) != os.fstat(source).st_size:
            raise CrateError('SOURCE_CHANGED', 4)
        # Reopen the original absolute path, not merely its pinned parent.
        fresh_parent = open_directory(path.parent)
        try:
            fresh_directory = os.fstat(fresh_parent)
            if (fresh_directory.st_dev, fresh_directory.st_ino) != parent_identity:
                raise CrateError('SOURCE_CHANGED', 4)
            fresh = open_regular_beneath(fresh_parent, path.name)
            try:
                if _metadata(os.fstat(fresh)) != before:
                    raise CrateError('SOURCE_CHANGED', 4)
            finally:
                os.close(fresh)
        finally:
            os.close(fresh_parent)
        return bytes(data), (parent_identity, before)
    except OSError as exc:
        raise CrateError('SPEC_READ_FAILED', 4, {'errno': exc.errno}) from exc
    finally:
        if source is not None:
            os.close(source)
        os.close(parent)


def _read_spec(path, limits):
    data, identity = _spec_bytes(path, limits)
    spec = load_spec(data)
    digest = hashlib.sha256(data).digest()

    def recheck():
        try:
            current, current_identity = _spec_bytes(path, limits)
        except CrateError as exc:
            if exc.exit_code == 5:
                raise
            raise CrateError('SOURCE_CHANGED', 4, {'input': 'selection'}) from exc
        if identity != current_identity or hashlib.sha256(current).digest() != digest:
            raise CrateError('SOURCE_CHANGED', 4, {'input': 'selection'})
    return spec, recheck


def _check_time(started, limits):
    if time.monotonic() - started > limits.job_wall_seconds:
        raise CrateError('BUDGET_EXCEEDED', 5, {'resource': 'job_wall_seconds'})


def _bootstrap_guard(sources, declared_paths=()):
    """Refuse input overlap before any tool bootstrap or temporary-file probe."""
    scratch = Path('/tmp')
    try:
        parent = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise CrateError('UNSAFE_SCRATCH_PARENT', 3, {'errno': exc.errno}) from exc
    try:
        info = os.fstat(parent)
        if not (info.st_uid in (0, os.geteuid()) and
                (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX)):
            raise CrateError('UNSAFE_SCRATCH_PARENT', 3)
        ancestors = _ancestors(parent)
    finally:
        os.close(parent)
    # Lexical protection does not open/acquire unused mappings. Concrete
    # admitted inputs cannot alias these paths through symlinks.
    for path in declared_paths:
        for protected in (path, protected_worktree_root(path)):
            if protected is not None and (protected == scratch or protected in scratch.parents):
                raise CrateError('SCRATCH_INSIDE_SOURCE', 3)
    for path in sources:
        for protected in (path, protected_worktree_root(path)):
            if protected is None:
                continue
            fd = open_directory(protected)
            try:
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) in ancestors:
                    raise CrateError('SCRATCH_INSIDE_SOURCE', 3)
            finally:
                os.close(fd)


def _guard_tool_locations(candidates, sources, protected_paths):
    """Read-only exclusion before explicit or internally resolved tools run."""
    if not protected_paths:
        return
    protected = set()
    for path in protected_paths:
        protected.add(path)
        worktree = protected_worktree_root(path)
        if worktree is not None:
            protected.add(worktree)
    for candidate in candidates:
        if not candidate.is_absolute() or '..' in candidate.parts:
            raise CrateError('UNTRUSTED_EXECUTABLE', 3)
        if any(path == candidate or path in candidate.parents for path in protected):
            raise CrateError('SOURCE_PATH_CANNOT_BE_TOOL', 3)
    # Actual identities are checked for admitted roots/packets. Unused mappings
    # are protected lexically above without being opened or acquired.
    identities = set()
    for source in sources:
        for path in (source, protected_worktree_root(source)):
            if path is None:
                continue
            fd = open_directory(path)
            try:
                info = os.fstat(fd)
                identities.add((info.st_dev, info.st_ino))
            finally:
                os.close(fd)
    for candidate in candidates:
        try:
            info = candidate.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise CrateError('UNTRUSTED_EXECUTABLE_PATH', 3)
            directory = candidate if stat.S_ISDIR(info.st_mode) else candidate.parent
            fd = _open_absolute_directory(directory, validate_endpoint=False)
            try:
                if identities & _ancestors(fd):
                    raise CrateError('SOURCE_PATH_CANNOT_BE_TOOL', 3)
            finally:
                os.close(fd)
        except OSError as exc:
            raise CrateError('TOOL_UNAVAILABLE', 3, {'errno': exc.errno}) from exc


def _explain(packet, repository, commit, path, job):
    result = explain_inclusion(packet.closure, repository, commit, path)
    if path is None:
        return result
    # A manifest alone does not establish an arbitrary requested path exists.
    phase = _phase(job, job.root / ('explain-' + secrets.token_hex(6)))
    _preflight_native(phase, (obj for obj in packet.closure.objects if obj.repository == repository))
    phase.native.run('init', {'name': repository, 'bare': True})
    _copy(packet.private_root / 'packet/repos' / (repository + '.bundle'),
          phase.root / 'artifacts' / (repository + '.bundle'), phase, job.limits.packet_bytes)
    phase.native.run('unbundle', {'repo': repository, 'name': repository})
    phase.native.run('install_seeds', {'repo': repository, 'oids': packet.closure.seeds[repository]})
    phase.native.run('fsck', {'repo': repository})
    reader = ObjectReader(AcquiredRepo(repository, phase.native._repo(repository), 'packet'), phase)
    tree = reader.commit(commit).tree
    entry = None
    parts = path.split('/')
    for index, part in enumerate(parts):
        entries = reader.tree(tree)
        phase.budget.charge('commit_path_visits', len(entries))
        entry = next((candidate for candidate in entries if candidate.name == part.encode('utf-8')), None)
        if entry is None or (index < len(parts) - 1 and entry.mode != 0o40000):
            raise CrateError('PATH_NOT_INCLUDED', 4, {'repository': repository, 'commit': commit, 'path': path})
        tree = entry.oid
    result['path_object'] = {'oid': entry.oid, 'mode': entry.mode,
                             'kind': 'tree' if entry.mode == 0o40000 else 'commit' if entry.mode == 0o160000 else 'blob'}
    for check in tuple(getattr(job, '_prepublication_checks', ())):
        check()
    return result


def _failure(exc, report, limits, job):
    published = publication_status(job) if job is not None else 'not-published'
    claimed = getattr(exc, 'context', {}).get('publication')
    committed = any(state in ('published', 'published-durability-uncertain')
                    for state in (published, claimed, report.get('publication')))
    if committed:
        error = CrateError('PUBLISHED_DURABILITY_UNCERTAIN', 6, {
            'publication': 'published-durability-uncertain',
            'cause': exc.code if isinstance(exc, CrateError) else type(exc).__name__})
    elif isinstance(exc, CrateError):
        error = exc
    elif isinstance(exc, KeyboardInterrupt):
        error = CrateError('CANCELLED', 130)
    elif isinstance(exc, OSError):
        error = CrateError('INTERNAL_IO_ERROR', 6, {'errno': exc.errno})
    else:
        error = CrateError('INTERNAL_INVARIANT', 6, {'exception_type': type(exc).__name__})
    report['status'] = 'blocked'
    report['publication'] = 'published-durability-uncertain' if committed else 'not-published'
    report['diagnostics'] = [error.to_dict()] if limits.diagnostics else []
    report['diagnostics_truncated'] = not limits.diagnostics or bool(error.context.get('diagnostics_truncated'))
    report['remediation'] = remediation(error.exit_code, report['publication'])
    return error.exit_code


def _main(argv=None):
    limits = Limits()
    started = time.monotonic()
    job = None
    report = base_report(limits)
    code = 0
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:  # argparse help is the sole text-stdout path.
            return int(exc.code)
        trust = bool(getattr(args, 'trust_local_data', False))
        overrides = _overrides(args.limit)
        limits = limits.lower(overrides)
        report = base_report(limits, trust, args.command)
        spec = None
        spec_guard = None
        if args.command in ('inspect', 'pack'):
            spec, spec_guard = _read_spec(args.spec, limits)
            limits = spec.limits.lower(overrides)
            spec = replace(spec, limits=limits)
            report['limits'] = limits.as_dict()
            if not spec.roots:
                raise CrateError('EMPTY_SELECTION', 3)
            if args.command == 'pack':
                validate_selection_output(spec, args.out)
        if args.command == 'restore':
            _name(args.root)
            _oid(args.commit)
        elif args.command == 'explain':
            _name(args.repo)
            _oid(args.commit)
            if args.path is not None:
                _path(args.path, limits)
        elif args.command == 'verify' and args.rehearse:
            _name(args.rehearse[0])
            _oid(args.rehearse[1])
        _check_time(started, limits)
        root_repositories = {root.repository for root in spec.roots} if spec is not None else set()
        sources = tuple(repo.git_dir for repo in spec.repositories if repo.id in root_repositories) if spec else ()
        if hasattr(args, 'packet'):
            sources = (_absolute(args.packet),)
        declared = tuple(path for repo in spec.repositories for path in (repo.git_dir, repo.lfs_objects_dir)) if spec else sources
        _bootstrap_guard(sources, declared)
        protected = (*declared, _absolute(args.out)) if hasattr(args, 'out') else declared
        def tool_guard(paths):
            _guard_tool_locations(paths, sources, protected)
        tool_guard((args.git, args.git_lfs))
        if args.command == 'doctor':
            report.update(doctor(args.git, args.git_lfs, limits, tool_guard=tool_guard))
            report['scope'] = 'Current toolchain and authored adapter capability probes; not release qualification.'
            report['trust_acknowledged'] = False
            report['observations']['detail'] = 'Capability observations appear in commands and safeguards.'
            _check_time(started, limits)
        else:
            # Pin before the fresh capability run; operations recheck the same
            # identities so an executable replacement cannot reuse qualification.
            tools = qualify_toolchain(args.git, args.git_lfs, limits, tool_guard=tool_guard)
            capabilities = doctor(args.git, args.git_lfs, limits, tool_guard=tool_guard)
            _check_time(started, limits)
            report['toolchain_checks'] = capabilities.get('checks', [])
            report['tools'] = {'git': str(tools.git), 'git_lfs': str(tools.git_lfs),
                               'git_version': tools.git_version, 'lfs_version': tools.lfs_version,
                               'sha256': dict(tools.hashes)}
            with Job(limits, tools, source_paths=sources) as job:
                job.native.started = started
                if spec_guard is not None:
                    spec_guard()
                    job._prepublication_checks = (spec_guard,)
                if args.command == 'inspect':
                    pool = RepositoryPool(spec, job)
                    closure = build_closure(spec, pool, job)
                    collect_payloads(closure, spec.repositories, job)
                    recheck_sources(job)
                    spec_guard()
                    report['diagnostics'] = selection_warnings(spec, closure)
                    report['counts'] = value(closure)['counts']
                    report['structural_checks'] = list(INSPECT_CHECKS)
                    report['status'] = 'ready'
                elif args.command == 'pack':
                    result = create_packet(spec, _absolute(args.out), job)
                    report['publication'] = publication_status(job)
                    report.update({key: result[key] for key in ('counts', 'structural_checks', 'rehearsed')})
                    report['diagnostics'] = result.get('warnings', [])
                    report['status'] = 'complete'
                else:
                    packet = verify_packet(_absolute(args.packet), job)
                    report['counts'] = value(packet.closure)['counts']
                    report['structural_checks'] = list(PACKET_CHECKS)
                    if args.command == 'restore':
                        restored = restore_verified(packet, args.root, args.commit, _absolute(args.out), job)
                        report['publication'] = publication_status(job)
                        report['rehearsed'] = [{'root': restored.root_id, 'commit': restored.commit}]
                        report['restoration_checks'] = list(restored.checks)
                    elif args.command == 'verify' and args.rehearse:
                        restored = restore_verified(packet, *args.rehearse, None, job)
                        report['rehearsed'] = [{'root': restored.root_id, 'commit': restored.commit}]
                        report['restoration_checks'] = list(restored.checks)
                    elif args.command == 'explain':
                        report['explanation'] = _explain(packet, args.repo, args.commit, args.path, job)
                    report['status'] = 'complete'
                _check_time(started, limits)
    except (Exception, KeyboardInterrupt) as exc:
        code = _failure(exc, report, limits, job)
    # Teardown already completed. Reporting errors still consult the receipt.
    try:
        observe(report, job, started)
        encoded = json.dumps(report, ensure_ascii=True, sort_keys=True, allow_nan=False)
    except (Exception, KeyboardInterrupt) as exc:
        fallback = base_report(limits, report.get('trust_acknowledged', False), report.get('command'))
        fallback['publication'] = report.get('publication', 'not-published')
        code = _failure(exc, fallback, limits, job)
        encoded = json.JSONEncoder(ensure_ascii=True, sort_keys=True, allow_nan=False).encode(fallback)
    try:
        sys.stdout.write(encoded + '\n')
        sys.stdout.flush()
    except (Exception, KeyboardInterrupt) as exc:
        # Partial stdout cannot be retried as another machine-readable report.
        state = publication_status(job) if job is not None else report.get('publication', 'not-published')
        state = 'published-durability-uncertain' if state != 'not-published' else state
        try:
            sys.stderr.write('historycrate: report output failed; publication=' + state + '\n')
        except (Exception, KeyboardInterrupt):
            pass
        return 130 if isinstance(exc, KeyboardInterrupt) and state == 'not-published' else 6
    return code


def main(argv=None):
    """Use a neutral scratch ancestor, never inherited TMPDIR probe locations.

    This process-local policy covers bootstrap qualification as well as Job.
    Restore it for callers embedding the CLI; source/packet inputs are guarded
    before the first allocation. The CLI deliberately does not honor TMPDIR.
    """
    previous = tempfile.tempdir
    tempfile.tempdir = '/tmp'
    try:
        return _main(argv)
    finally:
        tempfile.tempdir = previous
