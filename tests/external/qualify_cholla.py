#!/usr/bin/env python3
"""Opt-in Cholla API qualification; no downloads and no Cholla code execution.

Run from an installed HistoryCrate checkout, or with PYTHONPATH=src:. Supply all
three trusted fixture paths explicitly as arguments or CHOLLA_* environment
variables. --output-parent must be a private directory OUTSIDE the release tree.
This script deliberately is not collected as a test and never skips absent input.
The independent NativeOracle below imports no HistoryCrate module. Product imports
are confined to run_qualification(), the driver of the APIs under test.

The report distinguishes this API qualification from CLI qualification and from
historical native-bundle comparison. It measures the actual selected HistoryCrate
packet against the full frozen stores using the same 11 cached payloads. It does
not reproduce the old native-bundle baseline or claim OS containment/resource peaks.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zlib

RELEASE_ROOT = Path(__file__).resolve().parents[2]
CHUNK = 1024 * 1024


class QualificationFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise QualificationFailure(message)


def fingerprint(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), f'non-regular fixture file: {path}')
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            digest.update(block)
            size += len(block)
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            f'file changed while hashing: {path}')
    return {'size': size, 'sha256': digest.hexdigest(), 'mode': stat.S_IMODE(before.st_mode)}


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), f'input directory unavailable: {root}')
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            require(not (Path(directory)/name).is_symlink(), 'symlink directory in fixture')
        for name in sorted(files):
            path = Path(directory)/name
            result[path.relative_to(root).as_posix()] = fingerprint(path)
    return dict(sorted(result.items()))


def write_json(path, value):
    temporary = path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')
    os.replace(temporary, path)


def append_json(path, value):
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(value, sort_keys=True)+'\n')


def archive_files(roots, output):
    """Same bounded Python tar/gzip stream for full stores and actual packet.

    Sort regular members, retain modes, normalize timestamps/owners. No invented
    files, extra payloads, source deletions, or copies of the original scripts.
    """
    started = time.monotonic()
    members = [(label, root, inventory(root)) for label, root in sorted(roots.items())]
    count = size = 0
    with output.open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, compresslevel=9, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for label, root, records in members:
                    for relative, record in records.items():
                        info = tarfile.TarInfo(label+'/'+relative)
                        info.size, info.mode, info.mtime = record['size'], record['mode'], 0
                        info.uid = info.gid = 0
                        info.uname = info.gname = ''
                        with (root/relative).open('rb') as stream:
                            archive.addfile(info, stream)
                        count += 1
                        size += info.size
    return {'regular_files': count, 'regular_file_bytes': size,
            'compressed_bytes': output.stat().st_size, 'sha256': fingerprint(output)['sha256'],
            'elapsed_seconds': time.monotonic()-started,
            'implementation': {'python': platform.python_version(), 'zlib': zlib.ZLIB_RUNTIME_VERSION,
                               'tar': 'stdlib tarfile PAX regular members only, sorted, owner/time normalized',
                               'gzip': 'stdlib gzip compresslevel=9, mtime=0, filename empty, streaming'}}


class NativeOracle:
    """Native checks on owned copies only; independent of production traversal."""
    def __init__(self, git, lfs, git_exec, scratch, log):
        self.git_path, self.lfs, self.git_exec = Path(git), Path(lfs), Path(git_exec)
        self.scratch, self.log = Path(scratch), Path(log)
        self.scratch.mkdir(mode=0o700)
        for name in ('home', 'xdg', 'tmp', 'template'):
            (self.scratch/name).mkdir(mode=0o700)
        self.command_count = 0
        self.admitted_restores = set()
        self.env = {
            'PATH': str(self.git_path.parent)+':/usr/bin:/bin', 'GIT_EXEC_PATH': str(self.git_exec),
            'HOME': str(self.scratch/'home'), 'XDG_CONFIG_HOME': str(self.scratch/'xdg'),
            'TMPDIR': str(self.scratch/'tmp'), 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_ATTR_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
            'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0', 'GIT_ALLOW_PROTOCOL': '',
            'GIT_TEMPLATE_DIR': str(self.scratch/'template'), 'GIT_LFS_SKIP_SMUDGE': '1',
            'GIT_PAGER': 'cat', 'GIT_EDITOR': 'false', 'GIT_SEQUENCE_EDITOR': 'false', 'GOMAXPROCS': '2',
        }
        command = ('PATH='+shlex.quote(str(self.git_path.parent))+' GIT_EXEC_PATH='+
                   shlex.quote(str(self.git_exec))+' '+shlex.quote(str(self.lfs)))
        self.config = {
            'core.hooksPath': '/dev/null', 'core.attributesFile': '/dev/null', 'core.autocrlf': 'false',
            'core.filemode': 'true', 'core.ignorecase': 'false', 'core.fsmonitor': 'false',
            'core.untrackedCache': 'false', 'gc.auto': '0', 'maintenance.auto': 'false',
            'protocol.allow': 'never', 'protocol.file.allow': 'never', 'credential.helper': '',
            'credential.interactive': 'false', 'submodule.recurse': 'false', 'fetch.recurseSubmodules': 'false',
            'diff.external': '', 'filter.lfs.clean': command+' clean -- %f',
            'filter.lfs.smudge': command+' smudge --skip -- %f',
            'filter.lfs.process': command+' filter-process --skip', 'filter.lfs.required': 'true',
            'lfs.concurrenttransfers': '1',
        }
        self.identities = {str(p): p.stat() for p in (self.git_path, self.lfs, self.git_exec/'git')}

    def run(self, argv, cwd, data=b'', env=None, codes=(0,)):
        for filename, original in self.identities.items():
            now = Path(filename).stat()
            require((now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns) ==
                    (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns, original.st_ctime_ns),
                    'native tool changed during qualification')
        started = time.monotonic()
        # Output goes to bounded regular files rather than unbounded PIPE buffers.
        def child_limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (256*CHUNK, 256*CHUNK))
        with tempfile.TemporaryFile(dir=self.scratch) as out, tempfile.TemporaryFile(dir=self.scratch) as err:
            result = subprocess.run([str(x) for x in argv], cwd=cwd, env=env or self.env,
                                    input=data, stdout=out, stderr=err, timeout=300,
                                    preexec_fn=child_limits, check=False)
            out.seek(0); err.seek(0)
            stdout, stderr = out.read(256*CHUNK+1), err.read(CHUNK+1)
        self.command_count += 1
        append_json(self.log, {'argv': [str(x) for x in argv], 'cwd': str(cwd),
                              'elapsed_seconds': time.monotonic()-started, 'returncode': result.returncode,
                              'stdout_bytes': len(stdout), 'stdout_sha256': hashlib.sha256(stdout).hexdigest(),
                              'stderr_bytes': len(stderr), 'stderr_sha256': hashlib.sha256(stderr).hexdigest()})
        require(len(stdout) <= 256*CHUNK and len(stderr) <= CHUNK, 'oracle output bound exceeded')
        require(result.returncode in codes,
                f'native oracle command failed ({result.returncode}): {argv!r}: {stderr[:2000]!r}')
        return stdout, stderr, result.returncode

    def git(self, repo, *args, data=b'', attr_commit=None, codes=(0,)):
        argv = [self.git_path, '--no-pager']
        # Admitted restored repositories use ordinary native Git, with no -c
        # overrides masking missing/wrong persistent configuration.
        if Path(repo) not in self.admitted_restores:
            for key, value in self.config.items():
                argv += ['-c', key+'='+value]
        environment = dict(self.env)
        if attr_commit:
            environment['GIT_ATTR_SOURCE'] = attr_commit
        return self.run([*argv, *args], repo, data, environment, codes)[0]

    def copy_object_stage(self, original, target, *, bare):
        """Copy only pack/idx/rev and loose object bytes; never refs/config/info.

        No alternates, object info, commit-graphs, source HEAD, hooks, templates,
        attributes or configuration are imported. Native Git never runs in original.
        """
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        args = ['init', '--quiet', '--object-format=sha1', '--initial-branch=main', '--template=']
        if bare:
            args.append('--bare')
        self.git(target, *args)
        destination = target/'objects' if bare else target/'.git/objects'
        for relative in inventory(Path(original)/'objects'):
            if re.fullmatch(r'pack/pack-[0-9a-f]{40}\.(pack|idx|rev)', relative) or re.fullmatch(r'[0-9a-f]{2}/[0-9a-f]{38}', relative):
                out = destination/relative
                out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copyfile(Path(original)/'objects'/relative, out)
        for key, value in self.config.items():
            self.git(target, 'config', '--local', key, value)
        return target

    def tree(self, repo, commit):
        found = {}
        for record in self.git(repo, 'ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
            if not record:
                continue
            header, raw_path = record.split(b'\t', 1)
            mode, kind, oid = header.decode('ascii').split()
            path = raw_path.decode('utf-8')
            require(path not in found and not path.startswith('/') and '..' not in path.split('/'), 'invalid native tree path')
            found[path] = (int(mode, 8), kind, oid)
        return found

    def check_local_config(self, repo):
        """Parse config as data from neutral cwd before native repository access."""
        config = repo/'.git/config'
        require(config.is_file() and not config.is_symlink(), 'missing owned native config')
        raw = self.git(self.scratch, 'config', '--null', '--no-includes', '--file', str(config), '--list')
        allowed = {k.lower(): v for k, v in self.config.items()}
        allowed.update({'core.repositoryformatversion': '0', 'core.bare': 'false', 'core.logallrefupdates': 'true',
                        'core.pager': 'cat', 'diff.trustexitcode': 'false', 'pack.threads': '1', 'index.threads': '1',
                        'user.name': 'HistoryCrate Fixture', 'user.email': 'fixture@example.invalid', 'lfs.repositoryformatversion': '0'})
        observed = {}
        for item in raw.split(b'\0'):
            if not item:
                continue
            key, value = item.decode().split('\n', 1)
            observed.setdefault(key, []).append(value)
            if key.startswith('submodule.') and key.count('.') >= 2:
                field = key.rsplit('.', 1)[-1]
                safe = ((field == 'url' and value.startswith('historycrate-offline:')) or
                        (field == 'path' and not value.startswith('/') and '..' not in value.split('/')) or
                        (field, value) in {('active', 'true'), ('update', 'none'), ('ignore', 'none')})
                require(safe, 'unexpected persistent submodule config')
            else:
                require(key in allowed and value == allowed[key], f'unexpected persistent config: {key}')
        for key, value in self.config.items():
            require(observed.get(key.lower()) and set(observed[key.lower()]) == {value}, f'missing or wrong persistent config: {key}')
        for key in ('core.repositoryformatversion', 'core.bare', 'core.logallrefupdates'):
            require(observed.get(key) == [allowed[key]], f'missing native repository layout config: {key}')
        self.admitted_restores.add(Path(repo))

    def check_repository(self, repo, commit, payloads, expected_links):
        require((repo/'.git/HEAD').read_bytes() == (commit+'\n').encode(), 'HEAD is not exact detached pin')
        require(self.git(repo, 'rev-parse', '--verify', 'HEAD').strip().decode() == commit, 'native HEAD mismatch')
        require(self.git(repo, 'symbolic-ref', '-q', 'HEAD', codes=(1,)) == b'', 'symbolic HEAD')
        self.git(repo, 'fsck', '--full', '--strict', '--no-reflogs')
        tree = self.tree(repo, commit)
        require(set(payloads) <= set(tree), 'pinned LFS file absent from native tree')
        links = {p: item[2] for p, item in tree.items() if item[0] == 0o160000}
        require(links == expected_links, 'exact pinned gitlink set mismatch')
        index = {}
        for record in self.git(repo, 'ls-files', '-v', '--stage', '-z').split(b'\0'):
            if not record:
                continue
            header, path = record.split(b'\t', 1)
            flag, mode, oid, stage = header.split()
            require(flag == b'H' and stage == b'0', 'index flags or nonzero stage hide dirty content')
            name = path.decode('utf-8')
            require(name not in index, 'duplicate index record')
            index[name] = (int(mode, 8), oid.decode())
        require(index == {p: (entry[0], entry[2]) for p, entry in tree.items()}, 'index differs from pinned native tree')
        expected_paths = set(tree)
        for path in tree:
            expected_paths.update('/'.join(path.split('/')[:n]) for n in range(1, len(path.split('/'))))
        actual_paths = set()
        def visit(directory, prefix=''):
            for entry in directory.iterdir():
                if not prefix and entry.name == '.git':
                    continue
                name = prefix+entry.name
                actual_paths.add(name)
                require(not entry.is_symlink(), 'unexpected worktree symlink')
                if entry.is_dir() and name not in links:
                    visit(entry, name+'/')
        visit(repo)
        require(actual_paths == expected_paths, 'extra or missing worktree paths (including ignored paths)')
        for path, (mode, kind, oid) in sorted(tree.items()):
            target = repo/path
            if mode == 0o160000:
                require(target.is_dir(), 'gitlink path is not directory')
                continue
            require(kind == 'blob' and mode in (0o100644, 0o100755), 'unsupported pinned tree mode')
            record = fingerprint(target)
            require(record['mode'] == (mode & 0o777), f'worktree mode mismatch: {path}')
            blob = self.git(repo, 'cat-file', 'blob', oid)
            if path in payloads:
                expected = payloads[path]
                pointer = (f'version https://git-lfs.github.com/spec/v1\noid sha256:{expected["sha256"]}\nsize {expected["size"]}\n').encode()
                require(blob == pointer, f'pinned committed LFS pointer mismatch: {path}')
                for payload in (target, repo/'.git/lfs/objects'/expected['sha256'][:2]/expected['sha256'][2:4]/expected['sha256']):
                    info = fingerprint(payload)
                    require((info['size'], info['sha256']) == (expected['size'], expected['sha256']), f'payload bytes/hash mismatch: {path}')
            else:
                # Independent Git smudge/checkout conversion anchored to commit attributes.
                converted = self.git(repo, 'cat-file', '--filters', '--path='+path, oid, attr_commit=commit)
                require((record['size'], record['sha256']) == (len(converted), hashlib.sha256(converted).hexdigest()), f'checkout bytes mismatch: {path}')
            cleaned = self.git(repo, 'hash-object', '--path='+path, '--', path, attr_commit=commit)
            require(cleaned == (oid+'\n').encode(), f'native clean hash mismatch: {path}')
        cache = repo/'.git/lfs/objects'
        cached = inventory(cache) if cache.exists() else {}
        expected_cache = {x['sha256'][:2]+'/'+x['sha256'][2:4]+'/'+x['sha256']: x for x in payloads.values()}
        require(set(cached) == set(expected_cache), 'unexpected or missing LFS cache members')
        for path, record in cached.items():
            require(record['mode'] == 0o644, 'LFS cache mode mismatch')
        for args in [('diff', '--cached', '--no-ext-diff', '--no-textconv', '--ignore-submodules=none', '--exit-code', 'HEAD', '--'),
                     ('diff', '--no-ext-diff', '--no-textconv', '--ignore-submodules=none', '--exit-code', '--'),
                     ('status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none')]:
            require(self.git(repo, *args) == b'', 'native diff/status is not clean')
        if payloads:
            self.run([self.lfs, 'fsck', '--objects', '--pointers', commit], repo)
        return {'commit': commit, 'tracked_files': len(tree)-len(links), 'hydrated_files': len(payloads)}

    def check_restore(self, output, rehearsal, child_path='cholla-tests-data'):
        child = rehearsal['submodule_commit']
        if child is None:
            require(not (output/child_path).exists() and not (output/'.git/modules').exists(), 'absent child path/repository unexpectedly materialized')
        self.check_local_config(output)
        if child:
            require((output/child_path/'.git').is_dir(), 'expected embedded child repository missing')
            self.check_local_config(output/child_path)
        nodes = []
        if child:
            payloads = {x['path']: x for x in rehearsal['verified_lfs_files']}
            nodes.append(self.check_repository(output/child_path, child, payloads, {}))
        nodes.append(self.check_repository(output, rehearsal['root_commit'], {}, {child_path: child} if child else {}))
        raw = self.git(output, 'submodule', 'status', '--recursive')
        lines = raw.splitlines()
        if child:
            prefix = (' '+child+' '+child_path).encode()
            require(len(lines) == 1 and (lines[0] == prefix or (lines[0].startswith(prefix+b' (') and lines[0].endswith(b')'))), 'recursive native submodule status mismatch')
        else:
            require(not lines, 'absent child native status unexpectedly present')
        return {'root_commit': rehearsal['root_commit'], 'child_commit': child, 'repositories': len(nodes),
                'tracked_files': sum(n['tracked_files'] for n in nodes),
                'hydrated_files': sum(n['hydrated_files'] for n in nodes), 'checks': nodes}

    def historical_closure(self, stages, metadata):
        """Derive exact native commit/object/gitlink/pointer sets from pinned IDs."""
        selected = metadata['selection']
        seeds = {'cholla': selected['selected_root_commits'],
                 'cholla-data': selected['historical_dependency_seeds']}
        result = {'commits': [], 'objects': [], 'gitlinks': [], 'lfs': [], 'seeds': seeds}
        for repository, repo in stages.items():
            lines = self.git(repo, 'log', '--format=%H %T %P', *seeds[repository], '--').decode().splitlines()
            commits = {}
            for line in lines:
                oid, tree, *parents = line.split()
                require(oid not in commits, 'native duplicate selected commit')
                commits[oid] = {'repository': repository, 'oid': oid, 'tree': tree, 'parents': parents}
            result['commits'].extend(commits.values())
            oids = self.git(repo, 'rev-list', '--objects', '--no-object-names', *seeds[repository], '--').splitlines()
            require(len(set(oids)) == len(oids), 'duplicate native object traversal')
            infos = self.git(repo, 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)', data=b'\n'.join(oids)+b'\n')
            small = []
            for line in infos.decode().splitlines():
                oid, kind, size_text = line.split()
                size = int(size_text)
                result['objects'].append({'repository': repository, 'oid': oid, 'kind': kind, 'size': size})
                if kind == 'blob' and size <= 1024:
                    small.append(oid)
            pointers = {}
            raw = self.git(repo, 'cat-file', '--batch', data=('\n'.join(small)+'\n').encode()) if small else b''
            position = 0
            for expected_oid in small:
                end = raw.index(b'\n', position)
                oid, kind, size = raw[position:end].split()
                require(oid.decode() == expected_oid and kind == b'blob', 'native batch frame mismatch')
                position = end+1
                body = raw[position:position+int(size)]
                position += int(size)+1
                require(raw[position-1:position] == b'\n', 'native truncated blob frame')
                require(hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest() == expected_oid, 'native blob identity mismatch')
                match = re.fullmatch(rb'version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n', body)
                if match:
                    pointers[expected_oid] = (match[1].decode(), int(match[2]))
            require(position == len(raw), 'native extra batch frame')
            trees = {}
            for commit, record in commits.items():
                tree_id = record['tree']
                if tree_id not in trees:
                    trees[tree_id] = self.tree(repo, tree_id)
                for path, (mode, kind, oid) in trees[tree_id].items():
                    if mode == 0o160000:
                        result['gitlinks'].append({'parent_repository': repository, 'parent_commit': commit,
                                                  'path': path, 'child_commit': oid})
                    if oid in pointers and kind == 'blob':
                        sha, size = pointers[oid]
                        attrs = self.git(repo, 'check-attr', '--source='+commit, '-z', 'filter', '--', path).split(b'\0')
                        require(attrs == [path.encode(), b'filter', b'lfs', b''], 'canonical pointer lacks committed LFS filter')
                        result['lfs'].append({'repository': repository, 'commit': commit, 'path': path,
                                              'blob_oid': oid, 'sha256': sha, 'size': size})
        expected = metadata['expected_closure']
        for repository, prefix in [('cholla', 'root'), ('cholla-data', 'dependency')]:
            require(sum(x['repository'] == repository for x in result['commits']) == expected[prefix+'_commits'], 'pinned commit count mismatch')
            require(sum(x['repository'] == repository for x in result['objects']) == expected[prefix+'_git_objects'], 'pinned object count mismatch')
            require(sum(x['repository'] == repository and x['kind'] == 'tree' for x in result['objects']) == expected[prefix+'_tree_objects'], 'pinned tree count mismatch')
        require(sorted(x['oid'] for x in result['commits'] if x['repository'] == 'cholla-data') == selected['dependency_commit_ids'], 'exact child ancestor set mismatch')
        links = result['gitlinks']
        require(all(x['parent_repository'] == 'cholla' and x['path'] == selected['binding']['path'] for x in links), 'unexpected nested/historical gitlink')
        require(sorted({x['child_commit'] for x in links}) == selected['historical_dependency_seeds'], 'exact six historical seeds mismatch')
        require(len(result['lfs']) == expected['canonical_lfs_occurrences'], 'expected 34 LFS occurrences')
        require(all(x['repository'] == 'cholla-data' for x in result['lfs']), 'unexpected root LFS occurrence')
        payloads = {x['sha256']: {'size': x['size'], 'pointer_blob': x['blob_oid']} for x in result['lfs']}
        require(payloads == metadata['required_payloads'], 'exact pinned 11 payload/pointer identities differ')
        for key in ('commits', 'objects', 'gitlinks', 'lfs'):
            result[key].sort(key=lambda item: json.dumps(item, sort_keys=True))
        return result


def compare_manifest(packet, oracle, metadata, forbidden_paths):
    raw = (packet/'manifest.json').read_bytes()
    for path in forbidden_paths:
        require(str(path).encode() not in raw, 'source path leaked into semantic manifest')
    manifest = json.loads(raw)
    order = lambda rows: sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))
    for field in ('commits', 'objects', 'lfs'):
        require(order(manifest[field]) == oracle[field], f'exact native {field} set differs from packet')
    wanted = order(oracle['gitlinks'])
    actual = order([{key: row[key] for key in ('parent_repository', 'parent_commit', 'path', 'child_commit')} for row in manifest['gitlinks']])
    require(actual == wanted, 'exact historical gitlink occurrence set differs from packet')
    binding = metadata['selection']['binding']
    for row in manifest['gitlinks']:
        require(row['child_repository'] == binding['child_repository'] and
                row['url_sha256'] == hashlib.sha256(binding['url'].encode()).hexdigest(), 'historical binding identity mismatch')
    require({x['id']: x['seeds'] for x in manifest['repositories']} == oracle['seeds'], 'manifest seeds differ')
    require(len(manifest['roots']) == 1, 'unexpected root groups')
    root = manifest['roots'][0]
    require(root['id'] == metadata['selection']['root_id'] and root['repository'] == 'cholla' and
            root['commits'] == metadata['selection']['selected_root_commits'] and
            sorted(root['ancestors']) == sorted(x['oid'] for x in oracle['commits'] if x['repository'] == 'cholla'), 'exact root ancestors differ')
    payloads = {x['sha256']: x['size'] for x in manifest['payloads']}
    require(payloads == {key: value['size'] for key, value in metadata['required_payloads'].items()}, 'manifest payload inventory differs')
    require(manifest['counts']['commits'] == 2530 and manifest['counts']['objects'] == 15402 and
            manifest['counts']['lfs_occurrences'] == 34 and manifest['counts']['payloads'] == 11 and
            manifest['counts']['payload_bytes'] == 28989160, 'manifest pinned count mismatch')
    expected_members = {'manifest.json', 'COMPLETE.json', 'repos/cholla.bundle', 'repos/cholla-data.bundle'}
    expected_members.update('lfs/objects/'+oid[:2]+'/'+oid[2:4]+'/'+oid for oid in payloads)
    records = inventory(packet)
    require(set(records) == expected_members, 'unexpected actual packet members')
    for oid, size in payloads.items():
        item = records['lfs/objects/'+oid[:2]+'/'+oid[2:4]+'/'+oid]
        require(item['sha256'] == oid and item['size'] == size, 'packet actual payload mismatch')
    return manifest['counts'], records


def check_payload_cache(cache, expected):
    records = inventory(cache)
    require(set(records) == {oid[:2]+'/'+oid[2:4]+'/'+oid for oid in expected}, 'cache must contain exactly the pinned 11 payloads, no extra bloat')
    for oid, value in expected.items():
        record = records[oid[:2]+'/'+oid[2:4]+'/'+oid]
        require(record['sha256'] == oid and record['size'] == value['size'], 'pinned fixture cache payload mismatch')
    return records



def check_required_explanations(explain, closure, *, repository, parent_repository,
                                parent_commit, child_commit, child_path, payload):
    """Exercise the real explanation API against the intact verified closure."""
    dependency = explain(closure, repository, child_commit)
    requiring_payload = explain(closure, repository, child_commit, payload['path'])
    for result in (dependency, requiring_payload):
        require(result['repository'] == repository and result['commit'] == child_commit,
                'explanation target differs from the pinned historical child')
        require(any(reason.get('kind') == 'gitlink' and
                    reason.get('repository') == parent_repository and
                    reason.get('commit') == parent_commit and
                    reason.get('path') == child_path for reason in result['reasons']),
                'explanation omits the actual requiring root/child/path edge')
    require(requiring_payload.get('path') == payload['path'], 'explanation LFS path mismatch')
    expected = {'sha256': payload['sha256'], 'size': payload['size'], 'blob_oid': payload['pointer_blob']}
    require(requiring_payload.get('lfs') == [expected], 'explanation LFS identity/size mismatch')
    return {'source': 'intact verified recipient packet closure; immediate requiring edges',
            'dependency': dependency, 'requiring_payload': requiring_payload}


def run_cli_subprocess(command, evidence_dir, label):
    """Execute a fresh interpreter and persist exact output before validation.

    In-process CLI doctor is unsuitable after a large qualification: its lowered
    observer self-test deliberately requires observing a descendant, whereas a
    retained controller can itself exceed that test threshold. No product limit
    is modified. Each actual CLI process gets its own small controller.
    """
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    stdout_path = evidence_dir/(label+'.stdout')
    stderr_path = evidence_dir/(label+'.stderr')
    receipt_path = evidence_dir/(label+'.json')
    argv = [str(Path(sys.executable).resolve()), '-m', 'historycrate', *command]
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'PYTHONPATH': str(RELEASE_ROOT/'src'),
           'PYTHONNOUSERSITE': '1', 'PYTHONUNBUFFERED': '1', 'HOME': str(evidence_dir),
           'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
    record = {'argv': argv, 'cwd': str(RELEASE_ROOT), 'environment': env,
              'started_utc': datetime.now(timezone.utc).isoformat(), 'exit_code': None,
              'stdout_path': str(stdout_path), 'stderr_path': str(stderr_path)}
    started = time.monotonic()
    try:
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            result = subprocess.run(argv, cwd=RELEASE_ROOT, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, timeout=300, check=False)
        record['exit_code'] = result.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        record['invocation_failure'] = {'type': type(exc).__name__, 'message': str(exc)}
    finally:
        record['elapsed_seconds'] = time.monotonic()-started
        for kind, path in [('stdout', stdout_path), ('stderr', stderr_path)]:
            if path.exists():
                record[kind+'_fingerprint'] = fingerprint(path)
        # This persisted receipt exists even if parsing or later assertions fail.
        write_json(receipt_path, record)
    if stdout_path.exists():
        try:
            require(stdout_path.stat().st_size <= 16*CHUNK, 'CLI report exceeds harness read bound')
            record['stdout_report'] = json.loads(stdout_path.read_text())
        except (ValueError, UnicodeError, QualificationFailure) as exc:
            record['report_parse_failure'] = str(exc)
    write_json(receipt_path, record)
    return record


def exercise_missing_payload(packet, damaged, output, *, sha256,
                             root_id, root_commit, git, git_lfs, record=None):
    """Two isolated real CLI calls on one disposable copy; preserve originals."""
    intact_before = inventory(packet)
    require(not damaged.exists() and not output.exists(), 'negative targets must be fresh')
    shutil.copytree(packet, damaged)
    relative = 'lfs/objects/'+sha256[:2]+'/'+sha256[2:4]+'/'+sha256
    missing = damaged/relative
    require(fingerprint(missing)['sha256'] == sha256, 'wrong payload selected for negative case')
    missing.unlink()
    damaged_before = inventory(damaged)
    evidence_dir = damaged.parent/(damaged.name+'-cli-evidence')
    result = record if record is not None else {}
    result.update({'scope': 'isolated actual CLI verify and CLI restore negative calls',
                   'removed_member': relative, 'calls': [], 'evidence_directory': str(evidence_dir),
                   'provenance': 'No verified explanation is inferred from the damaged packet.'})
    common = ['--packet', str(damaged), '--git', str(git), '--git-lfs', str(git_lfs), '--trust-local-data']
    try:
        for command in (['verify', *common],
                        ['restore', *common, '--root', root_id, '--commit', root_commit, '--out', str(output)]):
            call = run_cli_subprocess(command, evidence_dir, command[0])
            result['calls'].append(call)  # Preserve failed calls, not only successful assertions.
            report = call.get('stdout_report', {})
            require(call['exit_code'] == 4 and report.get('status') == 'blocked' and
                    report.get('publication') == 'not-published',
                    'missing-payload CLI call did not fail closed with exit 4; see '+str(evidence_dir))
            codes = {item['code'] for item in report['diagnostics']}
            require(codes & {'INVALID_PACKET_LAYOUT', 'PACKET_HASH_MISMATCH', 'INCOMPLETE_PACKET'},
                    'missing-payload CLI failure is not an artifact/layout refusal')
            require(not output.exists(), 'missing-payload CLI call published a final output')
        require(inventory(damaged) == damaged_before, 'negative CLI calls changed damaged input')
    finally:
        result['intact_packet_unchanged'] = inventory(packet) == intact_before
        result['final_output_absent'] = not output.exists()
        require(result['intact_packet_unchanged'], 'negative case changed intact recipient packet')
        require(result['final_output_absent'], 'negative case left a final restore output')
    return result


def controller_sample():
    # A single Linux procfs observation. This is neither a maximum nor containment.
    result = {'monotonic_seconds': time.monotonic(), 'kind': 'instantaneous controller-only sample'}
    try:
        values = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        result['rss_bytes'] = int(values['VmRSS'].split()[0])*1024
        result['threads'] = int(values['Threads'])
    except (OSError, ValueError, KeyError):
        result['unavailable'] = True
    return result


@contextmanager
def phase(report, report_path, name):
    record = {'name': name, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'status': 'running', 'samples': [controller_sample()]}
    report['phases'].append(record)
    write_json(report_path, report)
    started = time.monotonic()
    try:
        yield record
    except BaseException as exc:
        record['status'] = 'failed'
        record['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
        if hasattr(exc, 'to_dict'):
            record['failure']['product_diagnostic'] = exc.to_dict()
        raise
    else:
        record['status'] = 'passed'
    finally:
        record['elapsed_seconds'] = time.monotonic()-started
        record['samples'].append(controller_sample())
        write_json(report_path, report)


def capture_job(job, record, directory):
    path = directory/(record['name']+'-native.jsonl')
    for command in job.native.records:
        append_json(path, command)
    observations = getattr(job, 'controller_observations', [])
    observation_path = directory/(record['name']+'-controller.jsonl')
    for observation in observations:
        append_json(observation_path, observation)
    record.update({'native_commands': len(job.native.records), 'native_log': path.name,
                   'controller_observation_records': len(observations), 'controller_log': observation_path.name,
                   'accounted_counters': dict(job.budget.used),
                   'job_limits': job.limits.as_dict()})


def run_qualification(args, metadata, sources, cache, work):
    # Only this driver imports product APIs. No oracle expectation uses a product checker.
    from historycrate.limits import Limits
    from historycrate.closure import explain_inclusion
    from historycrate.native import Job, doctor, qualify_toolchain
    from historycrate.packet import create_packet, verify_packet
    from historycrate.restore import restore_verified
    from historycrate.schema import load_spec

    report_path = work/'qualification.json'
    report = {'schema': 1, 'status': 'running', 'scope': 'real-Cholla API create_packet -> fresh Job verify_packet -> restore_verified',
              'cli_end_to_end_qualified': False, 'all_included_root_ancestors_rehearsed': False,
              'fixture': metadata['fixture_id'], 'phases': [], 'restorations': [],
              'invocation': [sys.executable, *sys.argv], 'python': platform.python_version(),
              'limitations': ['No Cholla code executed; no downloads; no native commands in frozen originals.',
                              'Only the three listed roots are rehearsed.',
                              'Observed samples are not maxima or OS containment claims.',
                              'The comparison is actual HistoryCrate packet vs full stores, not a rerun of the historical native-bundle baseline.'],
              'implementation_files': {p.relative_to(RELEASE_ROOT).as_posix(): fingerprint(p)
                                       for p in sorted((RELEASE_ROOT/'src/historycrate').glob('*.py'))},
              'harness_sha256': fingerprint(Path(__file__))['sha256'],
              'metadata_sha256': fingerprint(Path(__file__).with_name('cholla.json'))['sha256']}
    before = {}
    try:
        with phase(report, report_path, 'source-before') as record:
            before = {name: inventory(path) for name, path in sources.items()}
            require(sum(len(x) for x in before.values()) == 55, 'expected all 55 frozen source files')
            require(sum(v['size'] for x in before.values() for v in x.values()) == metadata['reference_measurements']['source_regular_file_bytes'], 'frozen source regular-byte count differs')
            for source in metadata['sources']:
                hashes = [item['sha256'] for name, item in before[source['id']].items() if re.fullmatch(r'objects/pack/pack-[0-9a-f]{40}\.pack', name)]
                require(hashes == [source['original_pack_sha256']], 'pinned original pack identity mismatch')
            write_json(work/'source-before.json', before)
            check_payload_cache(cache, metadata['required_payloads'])
            # Full-store archive already contains this same cache once, not an added duplicate.
            check_payload_cache(sources['cholla-data']/'lfs/objects', metadata['required_payloads'])
            record['regular_files'] = 55
        limits = Limits()
        with phase(report, report_path, 'doctor') as record:
            record['report'] = doctor(args.git, args.git_lfs, limits)
            tools = qualify_toolchain(args.git, args.git_lfs, limits)
            require(tools.hashes[str(args.git_lfs)] == metadata['required_runtime']['git_lfs_binary_sha256'], 'pinned LFS binary hash differs')
            report['toolchain'] = {'git_version': tools.git_version, 'git_lfs_version': tools.lfs_version,
                                   'git_exec_path': str(tools.git_exec_path), 'sha256': dict(tools.hashes)}
        oracle = NativeOracle(tools.git, tools.git_lfs, tools.git_exec_path, work/'oracle-private', work/'oracle-native.jsonl')
        with phase(report, report_path, 'independent-native-closure') as record:
            stages = {name: oracle.copy_object_stage(path, work/('oracle-'+name+'.git'), bare=True) for name, path in sources.items()}
            for source in metadata['sources']:
                # Exact full-store inventory without activating original refs/config.
                objects = oracle.git(stages[source['id']], 'cat-file', '--batch-all-objects', '--batch-check=%(objectname)').splitlines()
                require(len(objects) == source['original_pack_index_object_count'], 'full frozen object inventory differs')
                oracle.git(stages[source['id']], 'fsck', '--full', '--strict', '--no-reflogs', *[v['oid'] for v in source['recorded_refs'].values()])
            expected = oracle.historical_closure(stages, metadata)
            write_json(work/'independent-closure.json', expected)
            record.update({'native_commands_to_date': oracle.command_count,
                           'counts': {'commits': len(expected['commits']), 'objects': len(expected['objects']),
                                      'gitlinks': len(expected['gitlinks']), 'lfs_occurrences': len(expected['lfs'])}})
        spec_value = {'version': 1, 'repositories': [
            {'id': 'cholla', 'git_dir': str(sources['cholla'])},
            {'id': 'cholla-data', 'git_dir': str(sources['cholla-data']), 'lfs_objects_dir': str(cache)}],
            'roots': [{'id': metadata['selection']['root_id'], 'repository': 'cholla',
                       'commits': metadata['selection']['selected_root_commits']}],
            'bindings': [metadata['selection']['binding']]}
        write_json(work/'private-runtime-spec.json', spec_value)
        spec = load_spec(json.dumps(spec_value).encode())
        require(spec.limits == Limits(), 'qualification must keep unchanged frozen limits')
        packet = work/'created-packet'
        with phase(report, report_path, 'create-packet-api') as record:
            with Job(spec.limits, tools, output_parent=work, source_paths=tuple(sources.values())) as job:
                try:
                    record['result'] = create_packet(spec, packet, job)
                    require(record['result']['publication'] == 'published', 'packet was not successfully published')
                finally:
                    capture_job(job, record, work)
        counts, packet_inventory = compare_manifest(packet, expected, metadata, [*sources.values(), cache])
        report['counts'] = counts
        write_json(work/'packet-inventory.json', packet_inventory)
        recipient = work/'recipient-packet'
        shutil.copytree(packet, recipient)
        require(inventory(recipient) == packet_inventory, 'recipient copy differs')
        # This new Job has no original source paths/spec/acquired state. It receives
        # the copied recipient packet only. Creation's private scratch is already gone.
        with phase(report, report_path, 'recipient-verify-and-restore-api') as record:
            with Job(Limits(), tools, output_parent=work, source_paths=(recipient,)) as job:
                try:
                    verified = verify_packet(recipient, job)
                    record['verified_fresh_job'] = True
                    historical = metadata['rehearsals'][0]
                    required = historical['verified_lfs_files'][0]
                    record['explanations'] = check_required_explanations(
                        explain_inclusion, verified.closure, repository='cholla-data',
                        parent_repository='cholla', parent_commit=historical['root_commit'],
                        child_commit=historical['submodule_commit'], child_path='cholla-tests-data',
                        payload={**required, 'pointer_blob': metadata['required_payloads'][required['sha256']]['pointer_blob']})
                    for rehearsal in metadata['rehearsals']:
                        started = time.monotonic()
                        output = work/('restored-'+rehearsal['root_commit'])
                        restored = restore_verified(verified, metadata['selection']['root_id'], rehearsal['root_commit'], output, job)
                        report['restorations'].append({'root_commit': restored.commit, 'output': output.name,
                                                       'api_elapsed_seconds': time.monotonic()-started,
                                                       'product_checks': list(restored.checks)})
                        write_json(report_path, report)
                finally:
                    capture_job(job, record, work)
        with phase(report, report_path, 'independent-restored-output-checks') as record:
            for rehearsal, restored in zip(metadata['rehearsals'], report['restorations'], strict=True):
                started = time.monotonic()
                restored['independent_oracle'] = oracle.check_restore(work/restored['output'], rehearsal)
                restored['oracle_elapsed_seconds'] = time.monotonic()-started
            record['rehearsed_exact_root_commits'] = [x['root_commit'] for x in report['restorations']]
            record['native_commands_to_date'] = oracle.command_count
        with phase(report, report_path, 'missing-payload-negative-cli') as record:
            historical = metadata['rehearsals'][0]
            record.update(exercise_missing_payload(
                recipient, work/'damaged-packet', work/'blocked-restore',
                sha256=historical['verified_lfs_files'][0]['sha256'],
                root_id=metadata['selection']['root_id'], root_commit=historical['root_commit'],
                git=tools.git, git_lfs=tools.git_lfs, record=record))
        with phase(report, report_path, 'fair-streaming-comparison') as record:
            record['full_stores'] = archive_files(sources, work/'full-stores.tar.gz')
            record['selected_historycrate_packet'] = archive_files({'packet': recipient}, work/'historycrate-packet.tar.gz')
            record['same_exact_payload_count'] = 11
            record['same_exact_payload_bytes'] = 28989160
            record['lfs_cache_savings_bytes'] = 0
            record['comparison_kind'] = 'same streaming tar/gzip method; full frozen stores versus actual HistoryCrate selected packet'
        report['status'] = 'passed'
    except BaseException as exc:
        report['status'] = 'failed'
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
        if hasattr(exc, 'to_dict'):
            report['failure']['product_diagnostic'] = exc.to_dict()
        raise
    finally:
        # Always rehash originals, even after refused/failed native or product steps.
        if before:
            after = {name: inventory(path) for name, path in sources.items()}
            write_json(work/'source-after.json', after)
            report['original_sources_unchanged'] = before == after
            report['source_files_rehashed'] = sum(len(x) for x in after.values())
            if before != after:
                report['status'] = 'failed'
                report['source_failure'] = 'frozen originals changed'
            write_json(report_path, report)
            require(before == after, 'frozen originals changed during qualification')
        else:
            write_json(report_path, report)
    return report



def validate_continuation_inputs(args, metadata, sources, cache, prior_report_path):
    """Read-only admission for a narrowly scoped continuation of existing proof."""
    prior_report_path = Path(prior_report_path)
    require(prior_report_path.is_absolute(), 'continuation receipt must be an explicit absolute path')
    require(re.fullmatch(r'[0-9a-f]{64}', args.prior_report_sha256 or '') is not None,
            'continuation requires the reviewed original report SHA-256')
    require(fingerprint(prior_report_path)['sha256'] == args.prior_report_sha256,
            'original qualification receipt hash changed')
    prior = json.loads(prior_report_path.read_text())
    original = prior_report_path.parent
    require(prior['status'] == 'failed' and prior['fixture'] == metadata['fixture_id'],
            'continuation is only for this recorded failed qualification')
    phases = {item['name']: item for item in prior['phases']}
    required = ('source-before', 'doctor', 'independent-native-closure', 'create-packet-api',
                'recipient-verify-and-restore-api', 'independent-restored-output-checks')
    require(len(phases) == len(prior['phases']) and all(phases.get(name, {}).get('status') == 'passed' for name in required),
            'original expensive product/oracle gates did not all pass')
    require(phases.get('missing-payload-negative-cli', {}).get('status') == 'failed' and
            'fair-streaming-comparison' not in phases, 'unexpected continuation boundary')
    require(prior['original_sources_unchanged'] is True and prior['source_files_rehashed'] == 55,
            'original source immutability proof is incomplete')
    roots = [item['root_commit'] for item in metadata['rehearsals']]
    require([item['root_commit'] for item in prior['restorations']] == roots,
            'original exact three-restoration receipt differs')
    for actual, expected in zip(prior['restorations'], metadata['rehearsals'], strict=True):
        independent = actual['independent_oracle']
        require(independent['root_commit'] == expected['root_commit'] and
                independent['child_commit'] == expected['submodule_commit'] and
                independent['hydrated_files'] == len(expected['verified_lfs_files']),
                'original independent restored-output proof differs')
    metadata_record = fingerprint(Path(__file__).with_name('cholla.json'))
    require(metadata_record['sha256'] == prior['metadata_sha256'], 'fixture metadata changed')
    current_implementation = {p.relative_to(RELEASE_ROOT).as_posix(): fingerprint(p)
                              for p in sorted((RELEASE_ROOT/'src/historycrate').glob('*.py'))}
    require(current_implementation == prior['implementation_files'], 'production implementation changed since expensive qualification')
    selected_tools = {str(args.git), str(args.git_lfs), str(Path(prior['toolchain']['git_exec_path'])/'git')}
    require(set(prior['toolchain']['sha256']) == selected_tools and
            Path(prior['toolchain']['git_exec_path']).is_relative_to(args.git.parent.parent),
            'selected tool paths differ from original qualification')
    tool_hashes = {name: fingerprint(Path(name))['sha256'] for name in selected_tools}
    require(tool_hashes == prior['toolchain']['sha256'], 'qualified executable bytes changed')
    names = ('source-before.json', 'source-after.json', 'packet-inventory.json',
             'private-runtime-spec.json', 'independent-closure.json')
    receipts = {name: fingerprint(original/name) for name in names}
    receipts[prior_report_path.name] = fingerprint(prior_report_path)
    before = json.loads((original/'source-before.json').read_text())
    after = json.loads((original/'source-after.json').read_text())
    observed_sources = {name: inventory(path) for name, path in sources.items()}
    require(before == after == observed_sources and sum(len(items) for items in before.values()) == 55,
            'original 55 source files drifted from before/after receipts')
    spec = json.loads((original/'private-runtime-spec.json').read_text())
    require({row['id']: row['git_dir'] for row in spec['repositories']} == {name: str(path) for name, path in sources.items()},
            'explicit source paths differ from original runtime specification')
    require(next(row for row in spec['repositories'] if row['id'] == 'cholla-data')['lfs_objects_dir'] == str(cache),
            'explicit LFS cache differs from original runtime specification')
    saved_packet = json.loads((original/'packet-inventory.json').read_text())
    for name in ('created-packet', 'recipient-packet'):
        packet = original/name
        require(inventory(packet) == saved_packet, 'intact packet drifted from expensive verified receipt: '+name)
        expected_dirs = {''}
        for path in saved_packet:
            expected_dirs.update('/'.join(path.split('/')[:n]) for n in range(1, len(path.split('/'))))
        actual_dirs = {''} | {p.relative_to(packet).as_posix() for p in packet.rglob('*') if p.is_dir()}
        require(actual_dirs == expected_dirs, 'intact packet contains unexpected directories')
    require(len(saved_packet) == 15, 'expected exact 15-member intact packet')
    check_payload_cache(cache, metadata['required_payloads'])
    check_payload_cache(sources['cholla-data']/'lfs/objects', metadata['required_payloads'])
    check_payload_cache(original/'recipient-packet/lfs/objects', metadata['required_payloads'])
    return {'original_directory': str(original), 'original_receipt': str(prior_report_path),
            'original_receipt_sha256': args.prior_report_sha256,
            'original_harness_sha256': prior['harness_sha256'],
            'current_harness_sha256': fingerprint(Path(__file__))['sha256'],
            'original_status': prior['status'], 'original_failure': prior['failure'],
            'original_evidence_fingerprints': receipts, 'implementation_files': current_implementation,
            'tool_sha256': tool_hashes, 'metadata_fingerprint': metadata_record,
            'source_files_revalidated': 55, 'packet_members_revalidated': 15,
            'completed_phase_evidence': {name: phases[name] for name in required}}


def run_continuation(args, metadata, sources, cache, work, prior_report_path):
    """Continue only Step 7 and size comparison; never rewrite original evidence."""
    work, prior_report_path = Path(work), Path(prior_report_path)
    original = prior_report_path.parent
    require(work != original and original not in work.parents and work not in original.parents,
            'continuation output must be disjoint from original evidence')
    report_path = work/'qualification-continuation.json'
    report = {'schema': 1, 'status': 'running', 'phases': [],
              'scope': 'targeted continuation: isolated negative CLI calls and fair size comparison only',
              'original_qualification_receipt': str(prior_report_path),
              'positive_product_workflow': 'API gates and three independent restored-output checks remain in original receipt',
              'cli_end_to_end_qualified': False,
              'no_expensive_product_phases_reexecuted': True,
              'original_failure_preserved': True, 'invocation': [sys.executable, *sys.argv]}
    validated = None
    try:
        with phase(report, report_path, 'revalidate-existing-evidence') as record:
            validated = validate_continuation_inputs(args, metadata, sources, cache, prior_report_path)
            report['input_bindings'] = validated
            record['source_files_revalidated'] = 55
            record['packet_members_revalidated'] = 15
        with phase(report, report_path, 'missing-payload-negative-cli') as record:
            historical = metadata['rehearsals'][0]
            exercise_missing_payload(original/'recipient-packet', work/'damaged-packet', work/'blocked-restore',
                                     sha256=historical['verified_lfs_files'][0]['sha256'],
                                     root_id=metadata['selection']['root_id'], root_commit=historical['root_commit'],
                                     git=args.git, git_lfs=args.git_lfs, record=record)
        with phase(report, report_path, 'fair-streaming-comparison') as record:
            record['full_stores'] = archive_files(sources, work/'full-stores.tar.gz')
            record['selected_historycrate_packet'] = archive_files({'packet': original/'recipient-packet'}, work/'historycrate-packet.tar.gz')
            record.update({'same_exact_payload_count': 11, 'same_exact_payload_bytes': 28989160,
                           'lfs_cache_savings_bytes': 0,
                           'comparison_kind': 'same streaming tar/gzip method; full frozen stores versus actual verified HistoryCrate packet'})
        report['status'] = 'passed'
    except BaseException as exc:
        report['status'] = 'failed'
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        if validated is not None:
            try:
                after = validate_continuation_inputs(args, metadata, sources, cache, prior_report_path)
                require(after == validated, 'original evidence or inputs changed during continuation')
                report['original_evidence_and_inputs_unchanged'] = True
            except BaseException as exc:
                report['status'] = 'failed'
                report['original_evidence_and_inputs_unchanged'] = False
                report['after_check_failure'] = {'type': type(exc).__name__, 'message': str(exc)}
                write_json(report_path, report)
                raise
        write_json(report_path, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--run', action='store_true', help='explicitly opt in to the expensive full external run')
    parser.add_argument('--continue-from', type=Path, help='resume only failed Step 7 and unrun comparison from an existing receipt')
    parser.add_argument('--prior-report-sha256', help='reviewed SHA-256 required for --continue-from')
    parser.add_argument('--git-dir', type=Path, default=os.environ.get('CHOLLA_GIT_DIR'))
    parser.add_argument('--data-git-dir', type=Path, default=os.environ.get('CHOLLA_DATA_GIT_DIR'))
    parser.add_argument('--lfs-objects-dir', type=Path, default=os.environ.get('CHOLLA_LFS_OBJECTS_DIR'))
    parser.add_argument('--output-parent', type=Path, default=os.environ.get('CHOLLA_QUALIFICATION_OUTPUT_PARENT'))
    parser.add_argument('--git', type=Path, default=os.environ.get('HISTORYCRATE_GIT'))
    parser.add_argument('--git-lfs', type=Path, default=os.environ.get('HISTORYCRATE_GIT_LFS'))
    args = parser.parse_args(argv)
    work = None
    report_name = 'qualification-continuation.json' if args.continue_from else 'qualification.json'
    try:
        require(args.run, 'full external qualification requires explicit --run; nothing was launched')
        for name in ('git_dir', 'data_git_dir', 'lfs_objects_dir', 'output_parent', 'git', 'git_lfs'):
            value = getattr(args, name)
            require(value is not None, f'missing required --{name.replace("_", "-")} or corresponding environment variable')
            value = Path(value)
            require(value.is_absolute() and value.exists() and not value.is_symlink(), f'input unavailable or not an explicit absolute path: {name}')
            setattr(args, name, value)
        parent = args.output_parent.resolve()
        require(parent.is_dir() and parent.stat().st_uid == os.getuid() and not parent.stat().st_mode & 0o077, 'output parent must be a private operator-owned directory')
        require(parent != RELEASE_ROOT and RELEASE_ROOT not in parent.parents and parent not in RELEASE_ROOT.parents, 'full histories/assets must stay outside the release tree')
        for source in (args.git_dir, args.data_git_dir, args.lfs_objects_dir):
            source = source.resolve()
            require(parent != source and source not in parent.parents and parent not in source.parents, 'output parent must be disjoint from original sources/cache')
        sources = {'cholla': args.git_dir, 'cholla-data': args.data_git_dir}
        metadata = json.loads(Path(__file__).with_name('cholla.json').read_text())
        work = Path(tempfile.mkdtemp(prefix='cholla-qualification-', dir=parent))
        if args.continue_from:
            report = run_continuation(args, metadata, sources, args.lfs_objects_dir, work, args.continue_from)
        else:
            require(args.prior_report_sha256 is None, '--prior-report-sha256 requires --continue-from')
            report = run_qualification(args, metadata, sources, args.lfs_objects_dir, work)
        print(json.dumps({'status': report['status'], 'report': str(work/report_name)}))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps({'status': 'failed', 'failure': str(exc), 'type': type(exc).__name__,
                          'report': str(work/report_name) if work else None}), file=sys.stderr)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1


if __name__ == '__main__':
    raise SystemExit(main())
