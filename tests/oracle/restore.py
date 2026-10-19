"""Independent native acceptance oracle using original MIT fixture declarations.

The assertion code imports no production traversal, manifest, or restore checker.
Only the unittest driver invokes the public packet/restore APIs under test. Expected
files and gitlink targets come from HistoryBuilder declarations, cross-checked
with native ls-tree/cat-file against the original fixture repositories.
"""
from __future__ import annotations
from tests.toolchain import GIT as TEST_GIT, LFS as TEST_LFS, GIT_EXEC as TEST_GIT_EXEC

import hashlib
import importlib.util
from pathlib import Path
import stat
import shlex
import subprocess
import tempfile
import unittest

from tests.fixtures.histories import GIT, HistoryBuilder, inventory, modules, native

ROOT = Path(__file__).resolve().parents[2]


def _run(repo, *args, data=None):
    """Ordinary Git, outside the product adapter and without command config overrides."""
    env = {
        'PATH': str(TEST_GIT.parent)+':/usr/bin:/bin', 'HOME': str(Path(repo).parent),
        'XDG_CONFIG_HOME': '/dev/null', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_ATTR_NOSYSTEM': '1', 'GIT_NO_REPLACE_OBJECTS': '1',
        'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0',
        'GIT_OPTIONAL_LOCKS': '0', 'GOMAXPROCS': '2',
    }
    return subprocess.run([GIT, '--no-pager', *args], cwd=repo, env=env,
                          input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30, check=False)


def _git(case, repo, *args, data=None):
    result = _run(repo, *args, data=data)
    case.assertEqual(result.returncode, 0,
                     f'{repo}: git {args!r}\n{result.stderr.decode(errors="replace")}')
    return result.stdout


def _tree(case, repo, commit):
    result = {}
    for record in _git(case, repo, 'ls-tree', '-rz', commit).split(b'\0'):
        if not record:
            continue
        metadata, path = record.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        name = path.decode('utf-8')
        case.assertNotIn(name, result)
        result[name] = (int(mode, 8), kind.decode('ascii'), oid.decode('ascii'))
    return result


def _blob_oid(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def _assert_declared_tree(case, fixture, repository, commit, tree):
    declared = fixture.commits[repository][commit]
    expected = {}
    for path, value in declared['files'].items():
        if isinstance(value, tuple):
            mode, oid = value
        else:
            mode, oid = 0o100644, _blob_oid(value)
        expected[path] = (mode, 'commit' if mode == 0o160000 else 'blob', oid)
    case.assertEqual(tree, expected, 'native source tree differs from fixture declaration')
    case.assertEqual(_git(case, fixture.repos[repository], 'rev-parse', commit + '^{tree}')
                     .strip().decode(), declared['tree'])


def _config_entries(case, repo, *args):
    result = {}
    for item in _git(case, repo, 'config', *args, '--null', '--list').split(b'\0'):
        if item:
            key, value = item.decode('utf-8').split('\n', 1)
            if key in result:
                case.assertEqual(result[key], value, f'conflicting config key: {key}')
            result[key] = value
    return result


def _assert_owned_config(case, location, fixture, repo_id, oid, tree, links):
    config = _config_entries(case, location, '--local')
    for key, value in {
        'core.hookspath': '/dev/null', 'core.attributesfile': '/dev/null',
        'core.filemode': 'true', 'core.ignorecase': 'false', 'core.fsmonitor': 'false',
        'core.autocrlf': 'false', 'credential.helper': '',
        'protocol.allow': 'never', 'protocol.file.allow': 'never',
    }.items():
        case.assertEqual(config.get(key), value, f'unsafe or missing local config: {key}')
    lfs = shlex.quote(str(TEST_LFS))
    command = f'PATH={shlex.quote(str(TEST_GIT.parent))} GIT_EXEC_PATH={shlex.quote(str(TEST_GIT_EXEC))} {lfs}'
    expected_filters = {
        'filter.lfs.clean': command + ' clean -- %f',
        'filter.lfs.smudge': command + ' smudge --skip -- %f',
        'filter.lfs.process': command + ' filter-process --skip',
        'filter.lfs.required': 'true',
    }
    case.assertEqual({key: value for key, value in config.items() if key.startswith('filter.')},
                     expected_filters, 'unexpected executable filter configuration')
    expected_submodules = {}
    children = {path for path, entry in tree.items() if entry[0] == 0o160000}
    if children:
        metadata = _config_entries(case, fixture.repos[repo_id], '--blob=' + oid + ':.gitmodules')
        for path in children:
            names = [key[len('submodule.'):-len('.path')] for key, value in metadata.items()
                     if key.startswith('submodule.') and key.endswith('.path') and value == path]
            case.assertEqual(len(names), 1, f'fixture has no unique name for gitlink {path}')
            name = names[0]
            expected_submodules.update({
                f'submodule.{name}.path': path,
                f'submodule.{name}.url': 'historycrate-offline:' + links[repo_id, oid, path],
                f'submodule.{name}.active': 'true',
                f'submodule.{name}.update': 'none',
                f'submodule.{name}.ignore': 'none',
            })
    registrations = {key: value for key, value in config.items()
                     if key.startswith('submodule.') and key != 'submodule.recurse'}
    case.assertEqual(registrations, expected_submodules)
    allowed = {
        'core.repositoryformatversion', 'core.bare', 'core.logallrefupdates',
        'core.hookspath', 'core.attributesfile', 'core.autocrlf', 'core.filemode',
        'core.ignorecase', 'core.fsmonitor', 'core.untrackedcache', 'core.pager',
        'gc.auto', 'maintenance.auto', 'protocol.allow', 'protocol.file.allow',
        'credential.helper', 'credential.interactive', 'submodule.recurse',
        'fetch.recursesubmodules', 'diff.external', 'diff.trustexitcode',
        'pack.threads', 'index.threads', 'user.name', 'user.email',
        'lfs.concurrenttransfers', 'lfs.repositoryformatversion',
    } | set(expected_filters) | set(expected_submodules)
    case.assertEqual(set(config) - allowed, set(), 'unexpected copied or executable source config')
    case.assertEqual(config.get('diff.external', ''), '')
    case.assertEqual(config.get('core.pager'), 'cat')
    case.assertFalse((location / '.git/info/attributes').exists())
    hooks = location / '.git/hooks'
    case.assertFalse(hooks.exists() and any(hooks.iterdir()), 'unexpected installed hook files')


def _assert_worktree_inventory(case, root, tree):
    """Do not descend into child repositories or Git metadata; inspect each separately."""
    expected_files = {path for path, entry in tree.items() if entry[0] != 0o160000}
    children = {path for path, entry in tree.items() if entry[0] == 0o160000}
    expected_directories = set(children)
    for path in tree:
        expected_directories.update(str(parent) for parent in Path(path).parents
                                    if str(parent) != '.')
    actual_files, actual_directories = set(), set()

    def visit(directory, prefix=''):
        for item in directory.iterdir():
            relative = f'{prefix}/{item.name}' if prefix else item.name
            mode = item.lstat().st_mode
            case.assertFalse(stat.S_ISLNK(mode), f'symlink in restored worktree: {relative}')
            if relative == '.git':
                case.assertTrue(stat.S_ISDIR(mode), 'embedded .git must be a real directory')
                continue
            if stat.S_ISDIR(mode):
                actual_directories.add(relative)
                if relative not in children:
                    visit(item, relative)
            else:
                case.assertTrue(stat.S_ISREG(mode), f'nonregular worktree file: {relative}')
                actual_files.add(relative)

    visit(Path(root))
    case.assertEqual(actual_files, expected_files, 'unexpected or missing worktree files')
    case.assertEqual(actual_directories, expected_directories,
                     'unexpected or missing worktree directories')


def _assert_submodule_status(case, root, expected):
    lines = _git(case, root, 'submodule', 'status', '--recursive').splitlines()
    remaining = dict(expected)
    for line in lines:
        case.assertTrue(line.startswith(b' '), f'non-initialized/wrong/conflicted submodule: {line!r}')
        matched = []
        for path, oid in remaining.items():
            prefix = b' ' + oid.encode('ascii') + b' ' + path.encode('utf-8')
            if line == prefix or line.startswith(prefix + b' ('):
                matched.append(path)
        case.assertEqual(len(matched), 1, f'unexpected recursive submodule status: {line!r}')
        del remaining[matched[0]]
    case.assertEqual(remaining, {}, 'missing native recursive submodule status entries')


def assert_restored(case, root, fixture, repository, commit, links, *,
                    worktree_bytes=None, lfs_payloads=None):
    """Assert one restoration using independent expected trees and bytes.

    ``links[(repository, commit, path)] = child_repository`` declares each selected
    gitlink's local identity independently of the production binding/manifest.
    ``worktree_bytes`` declares converted ordinary file bytes, keyed the same way;
    ordinary files not listed must equal their original blob bytes. ``lfs_payloads``
    declares hydrated bytes at each LFS path. Neither map is derived from product
    results. Returns the independently checked repository occurrences.
    """
    worktree_bytes = worktree_bytes or {}
    lfs_payloads = lfs_payloads or {}
    checked = []
    all_submodules = {}

    def visit(location, repo_id, oid, prefix=''):
        source = fixture.repos[repo_id]
        declared = fixture.commits[repo_id][oid]
        tree = _tree(case, source, oid)
        _assert_declared_tree(case, fixture, repo_id, oid, tree)
        case.assertTrue((location / '.git').is_dir())
        case.assertFalse((location / '.git').is_symlink())
        case.assertEqual(_git(case, location, 'rev-parse', '--verify', 'HEAD').strip().decode(), oid)
        symbolic = _run(location, 'symbolic-ref', '-q', 'HEAD')
        case.assertEqual(symbolic.returncode, 1, 'restored HEAD must be detached')
        case.assertEqual(symbolic.stdout, b'')
        case.assertEqual(_git(case, location, 'rev-parse', 'HEAD^{tree}').strip().decode(),
                         declared['tree'])
        case.assertEqual(_git(case, location, 'cat-file', 'commit', 'HEAD'),
                         _git(case, source, 'cat-file', 'commit', oid))
        case.assertEqual(_tree(case, location, 'HEAD'), tree)
        _git(case, location, 'fsck', '--full', '--strict', '--no-reflogs', '--no-dangling')
        _assert_owned_config(case, location, fixture, repo_id, oid, tree, links)

        indexed = {}
        for record in _git(case, location, 'ls-files', '--stage', '-z').split(b'\0'):
            if not record:
                continue
            metadata, path = record.split(b'\t', 1)
            mode, blob, stage = metadata.split()
            name = path.decode('utf-8')
            case.assertEqual(stage, b'0', f'nonzero index stage: {name}')
            case.assertNotIn(name, indexed)
            indexed[name] = (int(mode, 8), blob.decode('ascii'))
        case.assertEqual(indexed, {path: (mode, blob) for path, (mode, _, blob) in tree.items()})
        for option in ('-v', '-f'):
            flagged = _git(case, location, 'ls-files', option, '-z').split(b'\0')
            case.assertEqual({record[2:].decode('utf-8') for record in flagged if record}, set(tree))
            for record in flagged:
                if record:
                    case.assertTrue(record.startswith(b'H '),
                                    f'index flag hides tracked content ({option}): {record!r}')

        _assert_worktree_inventory(case, location, tree)
        direct_children = []
        for path, (mode, kind, blob) in tree.items():
            key = repo_id, oid, path
            target = location / path
            if mode == 0o160000:
                case.assertIn(key, links, f'fixture lacks declared gitlink identity: {key}')
                child_id = links[key]
                child_prefix = f'{prefix}/{path}' if prefix else path
                all_submodules[child_prefix] = blob
                direct_children.append((target, child_id, blob, child_prefix))
                continue
            case.assertEqual(kind, 'blob')
            source_bytes = _git(case, source, 'cat-file', 'blob', blob)
            case.assertEqual(_git(case, location, 'cat-file', 'blob', blob), source_bytes)
            st = target.lstat()
            case.assertTrue(stat.S_ISREG(st.st_mode))
            case.assertEqual(st.st_nlink, 1, f'hardlinked worktree file: {path}')
            case.assertEqual(stat.S_IMODE(st.st_mode), 0o755 if mode == 0o100755 else 0o644)
            expected = lfs_payloads.get(key, worktree_bytes.get(key, source_bytes))
            case.assertEqual(target.read_bytes(), expected, f'wrong working bytes: {key}')
            if key in lfs_payloads:
                digest = hashlib.sha256(expected).hexdigest()
                pointer = (f'version https://git-lfs.github.com/spec/v1\n'
                           f'oid sha256:{digest}\nsize {len(expected)}\n').encode()
                case.assertEqual(source_bytes, pointer, 'fixture pointer disagrees with expected payload')
                cache = location / '.git/lfs/objects' / digest[:2] / digest[2:4] / digest
                cache_st = cache.lstat()
                case.assertTrue(stat.S_ISREG(cache_st.st_mode))
                case.assertEqual(cache_st.st_nlink, 1)
                case.assertNotEqual((st.st_dev, st.st_ino), (cache_st.st_dev, cache_st.st_ino))
                case.assertEqual(cache_st.st_size, len(expected))
                case.assertEqual(cache.read_bytes(), expected)
                case.assertEqual(hashlib.sha256(cache.read_bytes()).hexdigest(), digest)
            # Unconditional native clean/hash for every tracked regular file, even
            # when native status and cached timestamps would claim it is clean.
            cleaned = _git(case, location, 'hash-object', '--path=' + path, '--', path)
            case.assertEqual(cleaned.strip().decode('ascii'), blob,
                             f'normal native clean does not recover original blob: {key}')

        for child in direct_children:
            visit(*child)
        for options in ((), ('--cached',)):
            case.assertEqual(_git(case, location, 'diff', *options, '--no-ext-diff',
                                  '--no-textconv', '--ignore-submodules=none', '--exit-code'), b'')
        case.assertEqual(_git(case, location, 'status', '--porcelain=v1', '--untracked-files=all',
                              '--ignore-submodules=none'), b'')
        relative_submodules = {path[len(prefix)+1:] if prefix else path: child_oid
                               for path, child_oid in all_submodules.items()
                               if not prefix or path.startswith(prefix + '/')}
        _assert_submodule_status(case, location, relative_submodules)
        checked.append((prefix, repo_id, oid))

    visit(Path(root), repository, commit)
    return tuple(checked)


class IndependentRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from historycrate.limits import Limits
        from historycrate.native import qualify_toolchain
        cls.tools = qualify_toolchain(Path(GIT), TEST_LFS, Limits())

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('historycrate.restore'),
                             'recursive restore is not implemented')
        from historycrate import restore
        self.assertTrue(hasattr(restore, 'restore_verified'), 'restore_verified is not implemented')
        self.restore = restore.restore_verified
        self.temporary = tempfile.TemporaryDirectory(prefix='historycrate-oracle-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.fixture_root = self.base / 'sources'
        self.fixture_root.mkdir(mode=0o700)
        f = self.fixture = HistoryBuilder(self.fixture_root)
        for repo in ('main', 'child', 'leaf'):
            f.repository(repo)
        self.payload = b'Original MIT fixture payload\0\xff\n'
        sha = hashlib.sha256(self.payload).hexdigest()
        pointer = (f'version https://git-lfs.github.com/spec/v1\n'
                   f'oid sha256:{sha}\nsize {len(self.payload)}\n').encode()
        self.leaf = f.commit('leaf', {'leaf': b'nested historical leaf\n'})
        child_files = {
            '.gitmodules': modules(('deep', 'nested', '../leaf')),
            '.gitattributes': b'*.bin filter=lfs -text\n',
            'nested': (0o160000, self.leaf),
            "space apostrophe'.bin": (0o100755, f.blob('child', pointer)),
            '-leading.bin': pointer, 'semi;$(touch TRAP).bin': pointer,
            ':wq': b'colon path\n', 'empty.bin': b'',
            'ordinary-pointer': pointer, 'binary': b'\0\xff\r\n',
        }
        self.child = f.commit('child', child_files)
        # The demanded child is deliberately outside the source's current ancestry.
        self.unrelated_child = f.commit('child', {'unrelated': b'excluded current branch'})
        cache = f.repos['child'] / 'lfs/objects' / sha[:2] / sha[2:4]
        cache.mkdir(parents=True)
        (cache / sha).write_bytes(self.payload)
        self.first = f.commit('main', {
            '.gitmodules': modules(('original', 'old', '../child')),
            'old': (0o160000, self.child), '.gitignore': b'ignored-junk\n',
            'file': b'first\n',
        })
        self.deleted = f.commit('main', {
            '.gitmodules': modules(('original', 'old', '../child')),
            'old': b'former submodule is now an ordinary file\n',
            '.gitignore': b'ignored-junk\n', 'file': b'first\n',
        }, (self.first,))
        self.tip = f.commit('main', {
            '.gitmodules': modules(('moved', 'renamed', '../changed-url'),
                                   ('shared', 'shared', '../child')),
            '.gitattributes': b'*.txt text eol=crlf\nraw -text\n',
            '.gitignore': b'ignored-junk\n',
            'renamed': (0o160000, self.child), 'shared': (0o160000, self.child),
            'windows.txt': b'line one\nline two\n', 'raw': b'keep\r\n',
            'file': b'first\n',
        }, (self.deleted,))
        self.links = {
            ('main', self.first, 'old'): 'child',
            ('main', self.tip, 'renamed'): 'child',
            ('main', self.tip, 'shared'): 'child',
            ('child', self.child, 'nested'): 'leaf',
        }
        self.payloads = {('child', self.child, path): self.payload for path in
                         ("space apostrophe'.bin", '-leading.bin', 'semi;$(touch TRAP).bin')}
        self.working = {('main', self.tip, 'windows.txt'): b'line one\r\nline two\r\n'}
        self.spec = f.spec([('release', 'main', (self.tip,))], [
            ('main', 'old', '../child', 'child'),
            ('main', 'renamed', '../changed-url', 'child'),
            ('main', 'shared', '../child', 'child'),
            ('child', 'nested', '../leaf', 'leaf'),
        ])

    def job(self):
        from historycrate.native import Job
        return Job(self.spec.limits, self.tools,
                   source_paths=tuple(repo.git_dir for repo in self.spec.repositories))

    def verified(self, job):
        from historycrate.packet import build_packet, verify_packet
        packet, _ = build_packet(self.spec, job)
        return verify_packet(packet, job)

    def assert_output(self, output, commit):
        return assert_restored(self, output, self.fixture, 'main', commit, self.links,
                               worktree_bytes=self.working, lfs_payloads=self.payloads)

    def test_delete_reintroduce_rename_nested_shared_and_orphan_child(self):
        before = inventory(self.fixture_root)
        with self.job() as job:
            verified = self.verified(job)
            packet_before = inventory(verified.private_root)
            for index, commit in enumerate((self.first, self.deleted, self.tip)):
                with self.subTest(commit=commit):
                    output = self.base / f'restored-{index}'
                    self.restore(verified, 'release', commit, output, job)
                    checked = self.assert_output(output, commit)
                    self.assertEqual(len(checked), {self.first: 3, self.deleted: 1, self.tip: 5}[commit])
                    self.assertFalse(any(path.name == 'TRAP' for path in output.rglob('*')))
            self.assertEqual(inventory(verified.private_root), packet_before)
            # Native ancestry confirms this is genuinely an orphan-demand fixture.
            self.assertNotIn(self.child.encode(), native(self.fixture.repos['child'], 'rev-list', 'main'))
        self.assertEqual(inventory(self.fixture_root), before)

    def test_oracle_rejects_skip_worktree_and_assume_unchanged_flags(self):
        with self.job() as job:
            output = self.base / 'flags'
            self.restore(self.verified(job), 'release', self.deleted, output, job)
            self.assert_output(output, self.deleted)
            for enable, disable in (('--skip-worktree', '--no-skip-worktree'),
                                    ('--assume-unchanged', '--no-assume-unchanged')):
                with self.subTest(flag=enable):
                    native(output, 'update-index', enable, '--', 'file')
                    self.assertEqual(native(output, 'status', '--porcelain=v1'), b'')
                    with self.assertRaisesRegex(AssertionError, 'index flag'):
                        self.assert_output(output, self.deleted)
                    native(output, 'update-index', disable, '--', 'file')
            self.assert_output(output, self.deleted)

    def test_oracle_rejects_ignored_extras_and_wrong_working_bytes(self):
        with self.job() as job:
            output = self.base / 'content'
            self.restore(self.verified(job), 'release', self.deleted, output, job)
            self.assert_output(output, self.deleted)
            (output / 'ignored-junk').write_bytes(b'not in original tree')
            self.assertEqual(native(output, 'status', '--porcelain=v1', '--untracked-files=all'), b'')
            with self.assertRaisesRegex(AssertionError, 'worktree files'):
                self.assert_output(output, self.deleted)
            (output / 'ignored-junk').unlink()
            original = (output / 'file').read_bytes()
            (output / 'file').write_bytes(b'wrong\n')
            with self.assertRaisesRegex(AssertionError, 'working bytes'):
                self.assert_output(output, self.deleted)
            (output / 'file').write_bytes(original)
            self.assert_output(output, self.deleted)

    def test_oracle_rejects_wrong_detached_head_and_lfs_cache_bytes(self):
        with self.job() as job:
            output = self.base / 'identities'
            self.restore(self.verified(job), 'release', self.tip, output, job)
            self.assert_output(output, self.tip)
            child = output / 'renamed'
            native(child, 'symbolic-ref', 'HEAD', 'refs/historycrate/commits/' + self.child)
            with self.assertRaisesRegex(AssertionError, 'HEAD must be detached'):
                self.assert_output(output, self.tip)
            native(child, 'update-ref', '--no-deref', 'HEAD', self.child)
            digest = hashlib.sha256(self.payload).hexdigest()
            cache = child / '.git/lfs/objects' / digest[:2] / digest[2:4] / digest
            cache.write_bytes(b'!' * len(self.payload))
            with self.assertRaises(AssertionError):
                self.assert_output(output, self.tip)
            cache.write_bytes(self.payload)
            self.assert_output(output, self.tip)


if __name__ == '__main__':
    unittest.main()
