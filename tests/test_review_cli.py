"""Independent CLI review using original, owned, miniature local histories."""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from historycrate.cli import main
from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job, qualify_toolchain
from historycrate.model import RepoSpec
from historycrate.packet import create_packet
from tests.fixtures.histories import HistoryBuilder, inventory
from tests.toolchain import GIT, LFS, GIT_EXEC


class IndependentCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(GIT, LFS, Limits())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='historycrate-review-cli-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.builder = HistoryBuilder(self.root)
        self.source = self.builder.repository('source')
        self.base = self.builder.commit('source', {':wq': b'original', 'directory/file': b'data'})
        self.tip = self.builder.commit('source', {'-quoted\' path': b'new'}, (self.base,))
        self.unrelated = self.builder.commit('source', {'outside-selection': b'other'})
        self.spec = self.root/'selection.json'
        self.document = {'version': 1,
                         'repositories': [{'id': 'source', 'git_dir': str(self.source)}],
                         'roots': [{'id': 'release', 'repository': 'source', 'commits': [self.tip]}],
                         'bindings': []}
        self.write_spec()
        self.common = ['--git', str(GIT), '--git-lfs', str(LFS), '--trust-local-data']
        self.output = self.root/'output'

    def write_spec(self):
        self.spec.write_text(json.dumps(self.document))

    def invoke(self, args, stream=None):
        out, err = stream or io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(args)
        return code, json.loads(out.getvalue()), err.getvalue()

    def pack(self, extra=(), stream=None):
        return self.invoke(['pack', '--spec', str(self.spec), '--out', str(self.output),
                            *self.common, *extra], stream=stream)

    def saved_packet(self):
        packet = self.root/'packet'
        with Job(Limits(), self.tools) as job:
            create_packet(self.builder.spec([('release', 'source', (self.tip,))]), packet, job)
        return packet

    def test_data_command_help_discloses_trust_limits(self):
        for command in ('inspect', 'pack', 'verify', 'restore', 'explain'):
            with self.subTest(command=command):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = main([command, '--help'])
                text = out.getvalue()
                self.assertEqual(code, 0)
                self.assertIn('No OS sandbox', text)
                self.assertIn('--trust-local-data', text)

    def test_no_force_fetch_arbitrary_native_or_skip_check_options(self):
        for flag in ('--force', '--fetch', '--overwrite', '--skip-check', '--git-args', '--shell-command'):
            with self.subTest(flag=flag), patch('historycrate.cli.doctor', side_effect=AssertionError('native must not run')):
                code, report, err = self.pack([flag])
                self.assertEqual(code, 2, report)
                self.assertEqual(report['publication'], 'not-published')
                self.assertFalse(self.output.exists())

    def test_unknown_option_with_credentials_and_controls_is_redacted(self):
        secret = 'https://user:private-value@example.invalid/\x1b[31m'
        code, report, err = self.pack(['--unknown', secret])
        self.assertEqual(code, 2)
        self.assertNotIn('private-value', json.dumps(report)+err)
        self.assertNotIn('\x1b', err)

    def test_spec_ancestor_symlink_refused_before_native(self):
        alternate = self.root/'alias'
        alternate.symlink_to(self.root, target_is_directory=True)
        with patch('historycrate.cli.doctor', side_effect=AssertionError('native must not run')):
            code, report, _ = self.invoke(['pack', '--spec', str(alternate/'selection.json'),
                                          '--out', str(self.output), *self.common])
        self.assertEqual(code, 3, report)
        self.assertFalse(self.output.exists())

    def test_spec_writeable_by_others_or_directory_is_not_admitted(self):
        for kind in ('writable', 'directory'):
            with self.subTest(kind=kind), patch('historycrate.cli.doctor', side_effect=AssertionError('native must not run')):
                if kind == 'writable':
                    self.spec.chmod(0o666)
                else:
                    self.spec.unlink()
                    self.spec.mkdir()
                code, report, _ = self.pack()
                self.assertEqual(code, 3, report)
                self.assertFalse(self.output.exists())
                if kind == 'writable':
                    self.spec.chmod(0o600)

    def test_spec_in_place_mutation_during_read_is_detected(self):
        read = os.read
        identity = (self.spec.stat().st_dev, self.spec.stat().st_ino)
        changed = False

        def mutate(fd, length):
            nonlocal changed
            info = os.fstat(fd)
            if not changed and (info.st_dev, info.st_ino) == identity:
                changed = True
                with self.spec.open('ab') as stream:
                    stream.write(b' ')
            return read(fd, length)

        with patch('os.read', side_effect=mutate), patch('historycrate.cli.doctor', side_effect=AssertionError('native must not run')):
            code, report, _ = self.pack()
        self.assertTrue(changed)
        self.assertEqual(code, 4, report)
        self.assertEqual(report['diagnostics'][0]['code'], 'SOURCE_CHANGED')
        self.assertFalse(self.output.exists())

    def test_spec_mutation_after_snapshot_prevents_publication(self):
        before = inventory(self.source)

        def mutate_after_snapshot(*args, **kwargs):
            self.spec.write_bytes(self.spec.read_bytes()+b' ')
            return {'status': 'passed'}

        with patch('historycrate.cli.doctor', side_effect=mutate_after_snapshot):
            code, report, _ = self.pack()
        self.assertEqual(code, 4, report)
        self.assertEqual(report['publication'], 'not-published')
        self.assertFalse(self.output.exists())
        self.assertEqual(before, inventory(self.source))

    def test_spec_and_cli_lowered_caps_both_remain_in_success_report(self):
        self.document['limits'] = {'commits': 3, 'root_groups': 1}
        self.write_spec()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.invoke(['inspect', '--spec', str(self.spec), *self.common, '--limit', 'commits=2'])
        self.assertEqual(code, 0, report)
        self.assertEqual(report['limits']['commits']['threshold'], 2)
        self.assertEqual(report['limits']['root_groups']['threshold'], 1)
        self.assertEqual(report['counts']['commits'], 2)

    def test_inherited_temporary_directory_cannot_write_inside_source_or_packet(self):
        packet = self.saved_packet()
        cases = [(self.source, ['inspect', '--spec', str(self.spec), *self.common]),
                 (packet, ['verify', '--packet', str(packet), *self.common])]
        for protected, arguments in cases:
            for cached in (True, False):
                with self.subTest(protected=protected.name, cached=cached):
                    attempted = []
                    mkdir, open_file = os.mkdir, os.open

                    def guard_path(path):
                        path = Path(path)
                        if path == protected or protected in path.parents:
                            attempted.append(str(path))
                            # Stop a flawed implementation before its first input write.
                            raise AssertionError('attempted scratch creation inside an input')

                    def guarded_mkdir(path, *args, **kwargs):
                        guard_path(path)
                        return mkdir(path, *args, **kwargs)

                    def guarded_open(path, flags, *args, **kwargs):
                        if flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR):
                            guard_path(path)
                        return open_file(path, flags, *args, **kwargs)

                    before = inventory(protected)
                    prior = str(protected) if cached else None
                    with patch('tempfile.tempdir', prior), patch.dict(os.environ, {'TMPDIR': str(protected)}), \
                            patch('os.mkdir', side_effect=guarded_mkdir), patch('os.open', side_effect=guarded_open), \
                            patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
                        code, report, _ = self.invoke(arguments)
                        self.assertEqual(tempfile.tempdir, prior, 'temporary policy must be restored')
                    self.assertEqual(code, 0, report)
                    self.assertEqual(attempted, [], 'scratch creation must not even be attempted inside admitted inputs')
                    self.assertEqual(before, inventory(protected))

    def test_unused_declared_source_cache_and_worktree_protect_output_lexically(self):
        unused = self.root/'unused.git'
        cache = self.root/'unused-cache'
        worktree = self.root/'unselected-worktree'
        for directory in (unused, cache, worktree):
            directory.mkdir(mode=0o700)
            (directory/'keep').write_bytes(b'untouched')
        self.document['repositories'] += [
            {'id': 'unused', 'git_dir': str(unused), 'lfs_objects_dir': str(cache)},
            {'id': 'unselected', 'git_dir': str(worktree/'.git')}]
        self.write_spec()
        for protected in (unused, cache, worktree):
            with self.subTest(protected=protected.name):
                before = inventory(protected)
                output = protected/'new-packet'
                with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
                    code, report, _ = self.invoke(['pack', '--spec', str(self.spec), '--out', str(output), *self.common])
                self.assertEqual(code, 3, report)
                self.assertEqual(report['publication'], 'not-published')
                self.assertFalse(output.exists())
                self.assertEqual(before, inventory(protected))

    def test_neutral_scratch_ancestors_and_symlink_root_refuse_before_bootstrap(self):
        alias = self.root/'source-alias'
        alias.symlink_to(self.source, target_is_directory=True)
        for source in (Path('/'), Path('/tmp'), alias):
            with self.subTest(source=str(source)):
                self.document['repositories'][0]['git_dir'] = str(source)
                self.write_spec()
                with patch('tempfile.tempdir', str(self.root)), \
                        patch('historycrate.cli.qualify_toolchain', side_effect=AssertionError('bootstrap must not run')):
                    code, report, _ = self.pack()
                    self.assertEqual(tempfile.tempdir, str(self.root), 'failed preflight must restore temporary policy')
                self.assertEqual(code, 3, report)
                self.assertEqual(report['publication'], 'not-published')
                self.assertFalse(self.output.exists())

    def test_packet_api_unused_declarations_block_output_before_build(self):
        unused = self.root/'api-unused.git'
        cache = self.root/'api-cache'
        worktree = self.root/'api-worktree'
        for directory in (unused, cache, worktree):
            directory.mkdir(mode=0o700)
        spec = self.builder.spec([('release', 'source', (self.tip,))])
        spec = replace(spec, repositories=spec.repositories + (
            RepoSpec('unused', unused, cache),
            RepoSpec('worktree', worktree/'.git', worktree/'.git/lfs/objects')))
        for protected in (unused, cache, worktree):
            with self.subTest(protected=protected.name), Job(Limits(), self.tools) as job:
                with patch('historycrate.packet.build_packet', side_effect=AssertionError('build must not start')) as build:
                    with self.assertRaises(CrateError) as caught:
                        create_packet(spec, protected/'packet', job)
                    build.assert_not_called()
                self.assertEqual(caught.exception.exit_code, 3)
                self.assertFalse((protected/'packet').exists())

    def test_source_packet_cache_worktree_or_output_tools_never_reach_bootstrap(self):
        packet = self.saved_packet()
        unused = self.root/'tool-unused.git'
        cache = self.root/'tool-cache'
        worktree = self.root/'tool-worktree'
        for directory in (unused, cache, worktree, self.output):
            directory.mkdir(mode=0o700)
        self.document['repositories'] += [
            {'id': 'unused', 'git_dir': str(unused), 'lfs_objects_dir': str(cache)},
            {'id': 'unselected', 'git_dir': str(worktree/'.git')}]
        self.write_spec()
        for protected in (self.source, unused, cache, worktree, packet, self.output):
            for option, executable in (('--git', 'git'), ('--git-lfs', 'git-lfs')):
                with self.subTest(protected=protected.name, option=option):
                    selected = protected/executable
                    # Inert bytes only; intercept every bootstrap attempt so this
                    # fixture can never execute even on the flawed implementation.
                    selected.write_bytes(b'not an executable program\n')
                    selected.chmod(0o700)
                    common = list(self.common)
                    common[common.index(option)+1] = str(selected)
                    if protected == packet:
                        arguments = ['verify', '--packet', str(packet), *common]
                    else:
                        arguments = ['pack', '--spec', str(self.spec), '--out', str(self.output), *common]
                    try:
                        with patch('historycrate.native.run_process', side_effect=AssertionError('input code must not execute')) as run, \
                                patch('tempfile.TemporaryDirectory', side_effect=AssertionError('bootstrap must not allocate')) as allocate:
                            code, report, _ = self.invoke(arguments)
                        self.assertEqual(code, 3, report)
                        run.assert_not_called()
                        allocate.assert_not_called()
                        self.assertEqual(report['publication'], 'not-published')
                    finally:
                        selected.unlink()

    def test_qualifier_guard_runs_before_bootstrap_allocation(self):
        from historycrate import native as native_module

        def reject(paths):
            self.assertEqual(paths, (GIT, LFS))
            raise CrateError('REVIEW_TOOL_REFUSED', 3)

        with patch('tempfile.TemporaryDirectory', side_effect=AssertionError('must not allocate')) as allocate, \
                patch('historycrate.native.run_process', side_effect=AssertionError('must not execute')) as run:
            with self.assertRaises(CrateError) as caught:
                native_module.qualify_toolchain(GIT, LFS, Limits(), tool_guard=reject)
        self.assertEqual(caught.exception.code, 'REVIEW_TOOL_REFUSED')
        allocate.assert_not_called()
        run.assert_not_called()

    def test_qualifier_and_doctor_guard_exec_path_before_lfs_probe(self):
        from historycrate import native as native_module
        execute = native_module.run_process
        for qualify in (native_module.qualify_toolchain, native_module.doctor):
            with self.subTest(entry=qualify.__name__):
                calls, guards = [], []

                def record(argv, *args, **kwargs):
                    calls.append(tuple(argv))
                    self.assertEqual(argv[0], str(GIT), 'LFS must not be probed after rejected exec path')
                    return execute(argv, *args, **kwargs)

                def guard(paths):
                    guards.append(paths)
                    if GIT_EXEC in paths:
                        raise CrateError('REVIEW_EXEC_PATH_REFUSED', 3)

                with patch('historycrate.native.run_process', side_effect=record):
                    with self.assertRaises(CrateError) as caught:
                        qualify(GIT, LFS, Limits(), tool_guard=guard)
                self.assertEqual(caught.exception.code, 'REVIEW_EXEC_PATH_REFUSED')
                self.assertEqual(guards, [(GIT, LFS), (GIT_EXEC, GIT_EXEC/'git')])
                self.assertEqual([argv[-1] for argv in calls], ['--version', '--exec-path'])

    def test_unused_missing_inputs_warn_in_pack_without_acquisition(self):
        self.document['repositories'].append({'id': 'unused', 'git_dir': str(self.root/'missing')})
        self.document['bindings'].append({'parent_repository': 'source', 'path': 'unused',
                                          'url': 'https://owner:private-value@example.invalid/store',
                                          'child_repository': 'unused'})
        self.write_spec()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.pack(['--limit', 'diagnostics=2'])
        self.assertEqual(code, 0, report)
        self.assertEqual(report['counts']['repositories'], 1)
        self.assertEqual({x['code'] for x in report['diagnostics']}, {'UNUSED_REPOSITORY', 'UNUSED_BINDING'})
        self.assertNotIn('private-value', json.dumps(report))
        self.assertFalse(report['diagnostics_truncated'])
        self.assertTrue((self.output/'COMPLETE.json').is_file())

    def test_warning_overflow_blocks_before_packet_publication(self):
        self.document['repositories'] += [{'id': name, 'git_dir': str(self.root/name)} for name in ('unused_one', 'unused_two')]
        self.write_spec()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.pack(['--limit', 'diagnostics=1'])
        self.assertEqual(code, 5, report)
        self.assertTrue(report['diagnostics_truncated'])
        self.assertLessEqual(len(report['diagnostics']), 1)
        self.assertFalse(self.output.exists())

    def test_explain_real_punctuation_path_and_unselected_commit(self):
        packet = self.saved_packet()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.invoke(['explain', '--packet', str(packet), '--repo', 'source',
                                          '--commit', self.base, '--path', ':wq', *self.common])
            self.assertEqual(code, 0, report)
            self.assertEqual(report['explanation']['path'], ':wq')
            self.assertEqual(report['rehearsed'], [])
            code, report, _ = self.invoke(['explain', '--packet', str(packet), '--repo', 'source',
                                          '--commit', self.unrelated, *self.common])
        self.assertEqual(code, 4, report)
        self.assertNotIn('explanation', report)

    def test_explain_wont_use_tampered_packet_as_evidence(self):
        packet = self.saved_packet()
        manifest = packet/'manifest.json'
        manifest.write_bytes(manifest.read_bytes().replace(self.base.encode(), self.unrelated.encode()))
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.invoke(['explain', '--packet', str(packet), '--repo', 'source',
                                          '--commit', self.unrelated, *self.common])
        self.assertEqual(code, 4, report)
        self.assertNotIn('explanation', report)
        self.assertEqual(report['rehearsed'], [])

    def test_failed_rehearsal_never_claims_requested_revision_ran(self):
        packet = self.saved_packet()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.invoke(['verify', '--packet', str(packet), '--rehearse',
                                          'release', self.unrelated, *self.common])
        self.assertEqual(code, 3, report)
        self.assertEqual(report['diagnostics'][0]['code'], 'RESTORE_COMMIT_NOT_ALLOWED')
        self.assertEqual(report['rehearsed'], [])
        self.assertEqual(report['publication'], 'not-published')

    def test_successful_restore_lists_only_executed_revision(self):
        packet = self.saved_packet()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.invoke(['restore', '--packet', str(packet), '--root', 'release',
                                          '--commit', self.base, '--out', str(self.output), *self.common])
        self.assertEqual(code, 0, report)
        self.assertEqual(report['rehearsed'], [{'root': 'release', 'commit': self.base}])
        self.assertEqual(report['publication'], 'published')
        self.assertNotIn('verified', report)

    def test_output_write_failure_after_commit_preserves_uncertain_state(self):
        class InterruptFirstWrite(io.StringIO):
            first = True

            def write(self, value):
                if self.first:
                    self.first = False
                    raise KeyboardInterrupt
                return super().write(value)

        out, err = InterruptFirstWrite(), io.StringIO()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), redirect_stdout(out), redirect_stderr(err):
            code = main(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common])
        self.assertEqual(code, 6)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('publication=published-durability-uncertain', err.getvalue())
        self.assertTrue((self.output/'COMPLETE.json').is_file())

    def test_output_flush_failure_does_not_retry_success_json(self):
        class FailFlush(io.StringIO):
            def flush(self):
                raise OSError('injected flush failure')

        out, err = FailFlush(), io.StringIO()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), redirect_stdout(out), redirect_stderr(err):
            code = main(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common])
        self.assertEqual(code, 6)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertIn('publication=published-durability-uncertain', err.getvalue())
        self.assertTrue((self.output/'COMPLETE.json').is_file())

    def test_prepublication_output_interrupt_is_cancellation(self):
        class InterruptedOutput(io.StringIO):
            def write(self, value):
                raise KeyboardInterrupt

        out, err = InterruptedOutput(), io.StringIO()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), redirect_stdout(out), redirect_stderr(err):
            code = main(['inspect', '--spec', str(self.spec), *self.common])
        self.assertEqual(code, 130)
        self.assertIn('publication=not-published', err.getvalue())
        self.assertFalse(self.output.exists())

    def test_packet_return_error_preserves_real_receipt_not_exception_claim(self):
        def fail_after_real_publication(spec, output, job):
            create_packet(spec, output, job)
            raise CrateError('PRETEND_PREPUBLICATION_ERROR', 4, {'publication': 'not-published'})

        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), patch('historycrate.cli.create_packet', side_effect=fail_after_real_publication):
            code, report, _ = self.pack()
        self.assertEqual(code, 6, report)
        self.assertEqual(report['publication'], 'published-durability-uncertain')
        self.assertTrue((self.output/'COMPLETE.json').is_file())


class IndependentHarnessContinuationTests(unittest.TestCase):
    """Harness-only failures must retain evidence and never invent a passed gate."""
    def setUp(self):
        import importlib.util
        path = Path(__file__).parent/'external/qualify_cholla.py'
        spec = importlib.util.spec_from_file_location('independent_cholla_harness', path)
        self.q = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.q)
        self.temporary = tempfile.TemporaryDirectory(prefix='historycrate-review-continuation-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_isolated_cli_records_exact_malformed_output_before_validation(self):
        import hashlib
        import subprocess
        import sys
        evidence = self.root/'evidence'
        seen = []

        def intercepted(argv, **kwargs):
            seen.append(argv)
            self.assertEqual(argv[:3], [str(Path(sys.executable).resolve()), '-m', 'historycrate'])
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            self.assertFalse(kwargs.get('shell', False))
            self.assertEqual(kwargs['env']['PYTHONPATH'], str(self.q.RELEASE_ROOT/'src'))
            self.assertNotIn('INHERITED_HARNESS_SENTINEL', kwargs['env'])
            kwargs['stdout'].write(b'{partial-json\n')
            kwargs['stderr'].write(b'original failure detail\n')
            return subprocess.CompletedProcess(argv, 6)

        with patch.dict(os.environ, {'INHERITED_HARNESS_SENTINEL': 'not-forwarded'}), patch.object(self.q.subprocess, 'run', side_effect=intercepted):
            returned = self.q.run_cli_subprocess(['verify', '--help'], evidence, 'malformed')
        saved = json.loads((evidence/'malformed.json').read_text())
        self.assertEqual(saved, returned)
        self.assertEqual(saved['exit_code'], 6)
        self.assertIn('report_parse_failure', saved)
        self.assertNotIn('stdout_report', saved)
        self.assertEqual((evidence/'malformed.stdout').read_bytes(), b'{partial-json\n')
        self.assertEqual((evidence/'malformed.stderr').read_bytes(), b'original failure detail\n')
        self.assertEqual(saved['stdout_fingerprint']['sha256'], hashlib.sha256(b'{partial-json\n').hexdigest())
        self.assertEqual(len(seen), 1)

    def test_subprocess_invocation_failure_retains_partial_files_and_receipt(self):
        import subprocess
        for failure in (OSError('original synthetic spawn failure'), subprocess.TimeoutExpired(['original-test'], 300)):
            with self.subTest(failure=type(failure).__name__):
                evidence = self.root/type(failure).__name__

                def interrupted(argv, **kwargs):
                    kwargs['stdout'].write(b'partial-before-invocation-failure')
                    kwargs['stderr'].write(b'original stderr')
                    raise failure

                with patch.object(self.q.subprocess, 'run', side_effect=interrupted):
                    returned = self.q.run_cli_subprocess(['verify'], evidence, 'failed')
                saved = json.loads((evidence/'failed.json').read_text())
                self.assertEqual(saved, returned)
                self.assertIsNone(saved['exit_code'])
                self.assertEqual(saved['invocation_failure']['type'], type(failure).__name__)
                self.assertEqual((evidence/'failed.stdout').read_bytes(), b'partial-before-invocation-failure')
                self.assertEqual((evidence/'failed.stderr').read_bytes(), b'original stderr')

    def test_missing_payload_assertion_retains_failed_call_in_phase_record(self):
        import hashlib
        payload = b'original miniature review payload\n'
        sha = hashlib.sha256(payload).hexdigest()
        packet = self.root/'packet'
        member = packet/'lfs/objects'/sha[:2]/sha[2:4]/sha
        member.parent.mkdir(parents=True)
        member.write_bytes(payload)
        intact = self.q.inventory(packet)
        for index, (code, diagnostic) in enumerate(((6, 'OBSERVER_SELF_CHECK_DID_NOT_MEASURE_DESCENDANT'), (4, 'UNRELATED_FAILURE'))):
            with self.subTest(code=code, diagnostic=diagnostic):
                call = {'exit_code': code, 'stdout_report': {'status': 'blocked', 'publication': 'not-published', 'diagnostics': [{'code': diagnostic}]}}
                record = {}
                with patch.object(self.q, 'run_cli_subprocess', return_value=call) as invoke:
                    with self.assertRaises(self.q.QualificationFailure):
                        self.q.exercise_missing_payload(packet, self.root/f'damaged-{index}', self.root/f'output-{index}',
                            sha256=sha, root_id='release', root_commit='1'*40, git=GIT, git_lfs=LFS, record=record)
                self.assertEqual(record['calls'], [call])
                self.assertEqual(invoke.call_count, 1)
                self.assertTrue(record['intact_packet_unchanged'])
                self.assertTrue(record['final_output_absent'])
                self.assertEqual(self.q.inventory(packet), intact)

    def test_continuation_requires_exact_reviewed_receipt_before_input_admission(self):
        from types import SimpleNamespace
        prior = self.root/'qualification.json'
        prior.write_text('{"original": "receipt"}\n')
        for digest in (None, '', 'not-a-sha256', '0'*64):
            with self.subTest(digest=digest):
                with patch.object(self.q, 'inventory', side_effect=AssertionError('sources must not be opened')), patch.object(self.q.subprocess, 'run', side_effect=AssertionError('native must not run')):
                    with self.assertRaises(self.q.QualificationFailure):
                        self.q.validate_continuation_inputs(SimpleNamespace(prior_report_sha256=digest), {}, {}, self.root/'unused', prior)
        self.assertEqual(prior.read_text(), '{"original": "receipt"}\n')

    def test_continuation_rejects_incomplete_gates_and_changed_production_receipt(self):
        from types import SimpleNamespace
        import copy
        metadata = json.loads((Path(self.q.__file__).with_name('cholla.json')).read_text())
        required = ('source-before', 'doctor', 'independent-native-closure', 'create-packet-api',
                    'recipient-verify-and-restore-api', 'independent-restored-output-checks')
        template = {'status': 'failed', 'fixture': metadata['fixture_id'],
                    'phases': [{'name': n, 'status': 'passed'} for n in required] +
                              [{'name': 'missing-payload-negative-cli', 'status': 'failed'}],
                    'original_sources_unchanged': True, 'source_files_rehashed': 55,
                    'metadata_sha256': self.q.fingerprint(Path(self.q.__file__).with_name('cholla.json'))['sha256'],
                    'implementation_files': {p.relative_to(self.q.RELEASE_ROOT).as_posix(): self.q.fingerprint(p)
                                             for p in (self.q.RELEASE_ROOT/'src/historycrate').glob('*.py')},
                    'restorations': [{'root_commit': item['root_commit'], 'independent_oracle': {
                        'root_commit': item['root_commit'], 'child_commit': item['submodule_commit'],
                        'hydrated_files': len(item['verified_lfs_files'])}} for item in metadata['rehearsals']]}
        for mutation, expected in (('unfinished', 'gates'), ('production', 'implementation changed')):
            with self.subTest(mutation=mutation):
                prior_value = copy.deepcopy(template)
                if mutation == 'unfinished':
                    prior_value['phases'][4]['status'] = 'running'
                else:
                    prior_value['implementation_files']['src/historycrate/cli.py']['sha256'] = '0'*64
                prior = self.root/(mutation+'.json')
                prior.write_text(json.dumps(prior_value))
                before = prior.read_bytes()
                args = SimpleNamespace(prior_report_sha256=self.q.fingerprint(prior)['sha256'])
                with patch.object(self.q, 'inventory', side_effect=AssertionError('source admission must not happen')), patch.object(self.q.subprocess, 'run', side_effect=AssertionError('native must not run')):
                    with self.assertRaisesRegex(self.q.QualificationFailure, expected):
                        self.q.validate_continuation_inputs(args, metadata, {}, self.root/'unused', prior)
                self.assertEqual(prior.read_bytes(), before)

    def test_continuation_after_check_failure_cannot_leave_passed_receipt(self):
        from types import SimpleNamespace
        original = self.root/'original'; original.mkdir()
        prior = original/'qualification.json'
        original_bytes = b'{"status":"failed","evidence":"preserve exactly"}\n'
        prior.write_bytes(original_bytes)
        work = self.root/'continuation'; work.mkdir()
        metadata = {'rehearsals': [{'root_commit': '1'*40, 'verified_lfs_files': [{'sha256': '2'*64}]}],
                    'selection': {'root_id': 'release'}}
        args = SimpleNamespace(git=GIT, git_lfs=LFS)
        with patch.object(self.q, 'validate_continuation_inputs', side_effect=[{'bound': 'before'}, {'bound': 'changed'}]), patch.object(self.q, 'exercise_missing_payload', return_value={}), patch.object(self.q, 'archive_files', return_value={'synthetic': True}), patch.object(self.q, 'run_qualification', side_effect=AssertionError('expensive phases must never repeat')):
            with self.assertRaisesRegex(self.q.QualificationFailure, 'changed during continuation'):
                self.q.run_continuation(args, metadata, {}, self.root/'cache', work, prior)
        saved = json.loads((work/'qualification-continuation.json').read_text())
        self.assertEqual(saved['status'], 'failed')
        self.assertFalse(saved['original_evidence_and_inputs_unchanged'])
        self.assertIn('after_check_failure', saved)
        self.assertEqual(prior.read_bytes(), original_bytes)
