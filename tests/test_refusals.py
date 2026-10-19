"""CLI boundary regressions using only original, owned local fixture data.

Detailed native/object/metadata refusal matrices live in their owning modules;
these contracts prove those failures remain fail-closed at the public boundary.
"""
import dataclasses
import errno
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from historycrate.cli import main
from historycrate.errors import CrateError
from historycrate.limits import Limits
from historycrate.native import Job, qualify_toolchain
from historycrate.packet import create_packet
from tests.fixtures.histories import HistoryBuilder, inventory
from tests.toolchain import GIT, LFS


class ReportTests(unittest.TestCase):
    def test_neutral_scratch_parent_requires_safe_owner_and_sticky_permissions(self):
        from historycrate.cli import _bootstrap_guard
        for uid, mode in ((os.geteuid(), 0o40777), (os.geteuid() + 10000, 0o41777)):
            metadata = list(os.stat('/tmp'))
            metadata[0], metadata[4] = mode, uid
            with self.subTest(uid=uid, mode=mode), patch('historycrate.cli.os.fstat', return_value=os.stat_result(metadata)):
                with self.assertRaises(CrateError) as caught:
                    _bootstrap_guard(())
                self.assertEqual(caught.exception.code, 'UNSAFE_SCRATCH_PARENT')

    def test_observations_keep_sample_gaps_discovery_and_cleanup_uncertainty(self):
        from types import SimpleNamespace
        from historycrate.limits import Budget
        from historycrate.reports import base_report, observe
        limits = Limits()
        report = base_report(limits)
        first = {'max_sample_gap_seconds': 1.75, 'descendant_discovery_method': 'proc-task-children',
                 'cleanup': {'uncertain': True}, 'samples': [{}], 'processes': [{'max_rss_bytes': 1234}]}
        second = {'max_sample_gap_seconds': 2.5, 'descendant_discovery_method': 'bounded-procfs',
                  'cleanup': {'uncertain': False}, 'samples': [{}]}
        job = SimpleNamespace(native=SimpleNamespace(records=[{'observations': first}, {'observations': second}]),
                              controller_observations=[], budget=Budget(limits))
        observe(report, job, 0)
        summary = report['observations']
        self.assertEqual(summary.get('max_sample_gap_seconds'), 2.5)
        self.assertEqual(summary.get('descendant_discovery_methods'), ['bounded-procfs', 'proc-task-children'])
        self.assertEqual(summary.get('uncertain_cleanup_reports'), 1)
        self.assertEqual(summary['native_commands_observed'], 2)
        self.assertIn('records', summary.get('native_command_count_kind', ''))


class RefusalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = qualify_toolchain(GIT, LFS, Limits())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixtures = HistoryBuilder(self.root)
        self.source = self.fixtures.repository('source')
        self.commit = self.fixtures.commit('source', {'file': b'original\n'})
        self.spec = self.root / 'selection.json'
        self.document = {'version': 1, 'repositories': [{'id': 'source', 'git_dir': str(self.source)}],
                         'roots': [{'id': 'release', 'repository': 'source', 'commits': [self.commit]}], 'bindings': []}
        self.write_spec()
        self.output = self.root / 'output'
        self.common = ['--git', str(GIT), '--git-lfs', str(LFS), '--trust-local-data']

    def write_spec(self):
        self.spec.write_text(json.dumps(self.document))

    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                code = main(args)
            except Exception as exc:
                self.fail(f'CLI escaped instead of returning a bounded failure report: {type(exc).__name__}')
        return code, json.loads(stdout.getvalue()), stderr.getvalue()

    def pack(self, *extra):
        return self.invoke(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common, *extra])

    def assert_refusal(self, args, code, diagnostic=None):
        before = inventory(self.source)
        host = self.root / 'unrelated-host-file'
        host.write_bytes(b'untouched')
        result, report, _ = self.invoke(args)
        self.assertEqual(result, code, report)
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['publication'], 'not-published')
        self.assertEqual(report['rehearsed'], [])
        if diagnostic:
            self.assertEqual(report['diagnostics'][0]['code'], diagnostic)
        self.assertFalse(self.output.exists())
        self.assertEqual(before, inventory(self.source))
        self.assertEqual(host.read_bytes(), b'untouched')
        return report

    def test_required_trust_fails_before_any_native_or_input_read(self):
        with patch('historycrate.cli.doctor', side_effect=AssertionError('must not execute')):
            for command, params in (('inspect', ['--spec', str(self.spec)]),
                                    ('pack', ['--spec', str(self.spec), '--out', str(self.output)]),
                                    ('verify', ['--packet', str(self.root / 'absent')]),
                                    ('restore', ['--packet', str(self.root / 'absent'), '--root', 'release', '--commit', self.commit, '--out', str(self.output)]),
                                    ('explain', ['--packet', str(self.root / 'absent'), '--repo', 'source', '--commit', self.commit])):
                with self.subTest(command=command):
                    self.assert_refusal([command, *params, *self.common[:-1]], 2, 'INVALID_INVOCATION')

    def test_abbreviated_trust_flag_does_not_acknowledge_profile(self):
        self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output),
                             *self.common[:-1], '--trust'], 2, 'INVALID_INVOCATION')

    def test_malformed_duplicate_and_deep_spec_json_are_bounded_refusals(self):
        for raw in (b'{', b'{"version":1,"version":1}', b'[' * 65 + b']' * 65,
                    b'\xef\xbb\xbf{}', b'\xff', b'{"version":1.5}'):
            with self.subTest(raw=raw):
                self.spec.write_bytes(raw)
                self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 2, 'INVALID_SPEC')

    def test_syntactically_empty_selection_is_not_runtime_ready(self):
        self.document['roots'] = []
        self.write_spec()
        self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 3, 'EMPTY_SELECTION')

    def test_spec_symlink_hardlink_and_fifo_are_refused_without_following(self):
        target = self.root / 'target.json'
        self.spec.rename(target)
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    self.spec.symlink_to(target)
                elif kind == 'hardlink':
                    os.link(target, self.spec)
                else:
                    os.mkfifo(self.spec)
                try:
                    self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 3)
                finally:
                    self.spec.unlink()

    def test_spec_read_obeys_lowered_byte_cap_before_parsing(self):
        self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output),
                             *self.common, '--limit', 'spec_bytes=8'], 5, 'BUDGET_EXCEEDED')

    def test_every_profile_cap_cannot_be_raised(self):
        for field in dataclasses.fields(Limits()):
            with self.subTest(resource=field.name):
                self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output),
                                     *self.common, '--limit', f'{field.name}={field.default + 1}'], 2, 'INVALID_LIMIT')

    def test_invalid_limit_syntax_duplicate_and_spec_increase_refused(self):
        for extra in (['--limit', 'unknown=1'], ['--limit', 'commits=-1'], ['--limit', 'commits=1.5'],
                      ['--limit', 'commits=1', '--limit', 'commits=2']):
            with self.subTest(extra=extra):
                self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common, *extra], 2, 'INVALID_LIMIT')
        self.document['limits'] = {'commits': 1}
        self.write_spec()
        self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output),
                             *self.common, '--limit', 'commits=2'], 2, 'INVALID_LIMIT')

    def test_each_command_qualifies_capabilities_and_does_not_reuse_doctor_state(self):
        with patch('historycrate.cli.doctor', side_effect=CrateError('CAPABILITY_REFUSED', 3)):
            self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 3, 'CAPABILITY_REFUSED')

    def test_every_prepublication_marker_refusal_has_no_host_write_or_final_output(self):
        markers = ('shallow', 'commondir', 'worktrees', 'info/grafts', 'objects/info/alternates',
                   'objects/info/http-alternates', 'refs/replace/' + 'a' * 40, 'objects/pack/pack-' + 'a' * 40 + '.promisor')
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            for marker in markers:
                with self.subTest(marker=marker):
                    path = self.source / marker
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
                    try:
                        self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 3)
                    finally:
                        path.unlink()

    def test_lowered_traversal_budget_is_enforced_with_source_unchanged(self):
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            report = self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output),
                                          *self.common, '--limit', 'commits=0'], 5, 'BUDGET_EXCEEDED')
        self.assertEqual(report['limits']['commits']['threshold'], 0)

    def test_doctor_total_elapsed_budget_includes_capability_probe(self):
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), patch('historycrate.cli.time.monotonic', side_effect=[0.0, 0.0, 2.0, 2.0]):
            code, report, _ = self.invoke(['doctor', *self.common[:-1], '--limit', 'job_wall_seconds=1'])
        self.assertEqual(code, 5, report)
        self.assertEqual(report['diagnostics'][0]['code'], 'BUDGET_EXCEEDED')

    def test_missing_packet_and_malformed_pack_refuse_without_output(self):
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            self.assert_refusal(['restore', '--packet', str(self.root / 'absent'), '--root', 'release',
                                 '--commit', self.commit, '--out', str(self.output), *self.common], 4)
            malformed = self.source / 'objects/pack' / ('pack-' + 'a' * 40 + '.pack')
            malformed.write_bytes(b'PACK\x00malformed')
            self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 4)

    def test_malformed_packet_json_refused_before_restore_publication(self):
        packet = self.root / 'packet'
        with Job(Limits(), self.tools) as job:
            create_packet(self.fixtures.spec([('release', 'source', (self.commit,))]), packet, job)
        (packet / 'manifest.json').write_bytes(b'{"version":1,"version":1}')
        before = inventory(packet)
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            self.assert_refusal(['restore', '--packet', str(packet), '--root', 'release', '--commit', self.commit,
                                 '--out', str(self.output), *self.common], 4)
        self.assertEqual(before, inventory(packet))

    def test_spec_replacement_during_read_is_refused(self):
        original_read = os.read
        identity = (self.spec.stat().st_dev, self.spec.stat().st_ino)
        replaced = False
        def replace_on_read(fd, length):
            nonlocal replaced
            info = os.fstat(fd)
            if not replaced and (info.st_dev, info.st_ino) == identity:
                replacement = self.root / 'replacement-spec'
                replacement.write_bytes(b'{}')
                replacement.replace(self.spec)
                replaced = True
            return original_read(fd, length)
        with patch('os.read', side_effect=replace_on_read):
            self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 4, 'SOURCE_CHANGED')
        self.assertTrue(replaced)

    def test_spec_changed_after_loading_blocks_publication(self):
        def change_after_load(*args, **kwargs):
            self.spec.write_bytes(self.spec.read_bytes() + b'\n')
            return {'status': 'passed'}
        with patch('historycrate.cli.doctor', side_effect=change_after_load):
            self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 4, 'SOURCE_CHANGED')

    def test_cancellation_is_machine_readable_and_never_claims_publication(self):
        with patch('historycrate.cli.doctor', side_effect=KeyboardInterrupt):
            self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 130, 'CANCELLED')

    def test_prepublication_stdout_interrupt_retains_cancellation_exit(self):
        class InterruptOutput(io.StringIO):
            def write(self, text):
                raise KeyboardInterrupt
        stderr = io.StringIO()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), redirect_stdout(InterruptOutput()), redirect_stderr(stderr):
            code = main(['inspect', '--spec', str(self.spec), *self.common])
        self.assertEqual(code, 130)
        self.assertIn('publication=not-published', stderr.getvalue())

    def test_selected_source_tool_refused_before_qualification(self):
        candidate = self.source / 'tool-bin' / 'git'
        candidate.parent.mkdir(mode=0o700)
        candidate.write_bytes(b'#!/bin/sh\nexit 99\n')
        candidate.chmod(0o700)
        common = [*self.common]
        common[1] = str(candidate)
        with patch('historycrate.cli.qualify_toolchain', side_effect=AssertionError('source executable reached bootstrap')):
            self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *common],
                                 3, 'SOURCE_PATH_CANNOT_BE_TOOL')

    def test_qualifier_guard_runs_before_lfs_version_and_doctor_capabilities(self):
        import historycrate.native as native_module
        original = native_module.run_process
        for function in (native_module.qualify_toolchain, native_module.doctor):
            calls = []
            checked = []
            def process(args, *positional, **kwargs):
                calls.append(tuple(args))
                return original(args, *positional, **kwargs)
            def guard(paths):
                checked.extend(paths)
                if self.tools.git_exec_path in paths:
                    raise CrateError('TEST_GUARD_STOP', 3)
            with self.subTest(function=function.__name__), patch.object(native_module, 'run_process', side_effect=process):
                try:
                    with self.assertRaises(CrateError) as caught:
                        function(GIT, LFS, Limits(), tool_guard=guard)
                except TypeError:
                    self.fail('Qualification must expose the read-only tool location guard before native use')
                self.assertEqual(caught.exception.code, 'TEST_GUARD_STOP')
                self.assertIn(GIT, checked)
                self.assertIn(LFS, checked)
                self.assertIn(self.tools.git_exec_path, checked)
                self.assertFalse(any(command[0] == str(LFS) for command in calls))

    def test_unexpected_exception_is_bounded_and_redacted(self):
        with patch('historycrate.cli.doctor', side_effect=RuntimeError('https://user:secret@example.invalid')):
            report = self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output), *self.common], 6, 'INTERNAL_INVARIANT')
        self.assertNotIn('secret', json.dumps(report))

    def test_unused_missing_repository_is_warned_without_acquisition(self):
        self.document['repositories'].append({'id': 'unused', 'git_dir': str(self.root / 'does-not-exist')})
        self.write_spec()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.invoke(['inspect', '--spec', str(self.spec), *self.common])
        self.assertEqual(code, 0, report)
        self.assertEqual(report['counts']['repositories'], 1)
        self.assertEqual(report['diagnostics'][0]['code'], 'UNUSED_REPOSITORY')

    def test_diagnostic_truncation_is_a_blocked_result(self):
        self.document['repositories'].append({'id': 'unused', 'git_dir': str(self.root / 'does-not-exist')})
        self.write_spec()
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            report = self.assert_refusal(['pack', '--spec', str(self.spec), '--out', str(self.output),
                                          *self.common, '--limit', 'diagnostics=0'], 5)
        self.assertTrue(report['diagnostics_truncated'])
        self.assertEqual(report['diagnostics'], [])

    def test_packet_api_reports_exact_unused_binding_before_publication(self):
        from historycrate.model import Binding
        spec = self.fixtures.spec([('release', 'source', (self.commit,))])
        spec = dataclasses.replace(spec, bindings=(Binding('source', 'unused', 'https://user:secret@example.invalid/identity', 'source'),))
        with Job(spec.limits, self.tools) as job:
            report = create_packet(spec, self.output, job)
        self.assertIn('warnings', report)
        self.assertEqual(report['warnings'][0]['code'], 'UNUSED_BINDING')
        self.assertNotIn('secret', json.dumps(report))

    def test_packet_api_diagnostic_exhaustion_prevents_publication(self):
        from historycrate.model import Binding
        spec = self.fixtures.spec([('release', 'source', (self.commit,))])
        spec = dataclasses.replace(spec, bindings=(Binding('source', 'unused', 'identity', 'source'),),
                                   limits=Limits().lower({'diagnostics': 0}))
        with Job(spec.limits, self.tools) as job:
            with self.assertRaises(CrateError) as caught:
                create_packet(spec, self.output, job)
        self.assertEqual(caught.exception.code, 'DIAGNOSTIC_LIMIT')
        self.assertFalse(self.output.exists())

    def test_packet_warning_limit_respects_lowered_job_cap(self):
        from historycrate.model import Binding
        spec = self.fixtures.spec([('release', 'source', (self.commit,))])
        spec = dataclasses.replace(spec, bindings=(Binding('source', 'unused', 'identity', 'source'),))
        with Job(Limits().lower({'diagnostics': 0}), self.tools) as job:
            with self.assertRaises(CrateError) as caught:
                create_packet(spec, self.output, job)
        self.assertEqual(caught.exception.code, 'DIAGNOSTIC_LIMIT')
        self.assertFalse(self.output.exists())

    def test_packet_api_protects_unused_declared_worktree_without_acquiring_it(self):
        from historycrate.model import RepoSpec
        worktree = self.root / 'unselected-worktree'
        worktree.mkdir(mode=0o700)
        spec = self.fixtures.spec([('release', 'source', (self.commit,))])
        spec = dataclasses.replace(spec, repositories=(*spec.repositories, RepoSpec('unused', worktree / '.git', worktree / 'cache')))
        output = worktree / 'packet'
        with Job(spec.limits, self.tools) as job:
            with self.assertRaises(CrateError) as caught:
                create_packet(spec, output, job)
        self.assertEqual(caught.exception.code, 'PATH_OVERLAP')
        self.assertFalse(output.exists())

    def test_cleanup_error_after_commit_keeps_output_and_uncertainty(self):
        original_exit = Job.__exit__
        def broken_cleanup(job, typ, value, tb):
            original_exit(job, typ, value, tb)
            raise OSError(errno.EIO, 'injected cleanup failure')
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), patch.object(Job, '__exit__', broken_cleanup):
            code, report, _ = self.pack()
        self.assertEqual(code, 6, report)
        self.assertEqual(report['publication'], 'published-durability-uncertain')
        self.assertTrue((self.output / 'COMPLETE.json').is_file())

    def test_interruption_after_packet_return_reads_shared_publication_receipt(self):
        def interrupt_after_commit(spec, output, job):
            create_packet(spec, output, job)
            raise KeyboardInterrupt
        # The failure happens before the CLI receives any successful return value.
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), patch('historycrate.cli.create_packet', side_effect=interrupt_after_commit, create=True):
            code, report, _ = self.pack()
        self.assertEqual(code, 6, report)
        self.assertEqual(report['publication'], 'published-durability-uncertain')
        self.assertTrue((self.output / 'COMPLETE.json').is_file())

    def test_report_serialization_error_after_commit_keeps_output_and_uncertainty(self):
        original_dumps = json.dumps
        def broken_report(value, *args, **kwargs):
            if isinstance(value, dict) and value.get('report_version') == 1:
                raise ValueError('injected report failure')
            return original_dumps(value, *args, **kwargs)
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), patch('historycrate.cli.json.dumps', side_effect=broken_report):
            code, report, _ = self.pack()
        self.assertEqual(code, 6, report)
        self.assertEqual(report['publication'], 'published-durability-uncertain')
        self.assertTrue((self.output / 'COMPLETE.json').is_file())

    def test_explain_missing_path_never_fabricates_inclusion(self):
        with Job(Limits(), self.tools) as job:
            create_packet(self.fixtures.spec([('release', 'source', (self.commit,))]), self.root / 'packet', job)
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            report = self.assert_refusal(['explain', '--packet', str(self.root / 'packet'), '--repo', 'source',
                                          '--commit', self.commit, '--path', 'missing', *self.common], 4, 'PATH_NOT_INCLUDED')
        self.assertNotIn('explanation', report)

    def test_source_and_destination_alias_refused_without_source_writes(self):
        before = inventory(self.source)
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}):
            code, report, _ = self.invoke(['pack', '--spec', str(self.spec), '--out', str(self.source / 'packet'), *self.common])
        self.assertEqual(code, 3, report)
        self.assertEqual(report['publication'], 'not-published')
        self.assertEqual(before, inventory(self.source))

    def test_destination_creation_race_preserves_other_directory(self):
        from historycrate.paths import atomic_publish
        def race(stage, destination):
            destination.mkdir(mode=0o700)
            (destination / 'belongs-to-other-writer').write_bytes(b'preserve')
            return atomic_publish(stage, destination)
        before = inventory(self.source)
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), patch('historycrate.paths.atomic_publish', side_effect=race):
            code, report, _ = self.pack()
        self.assertEqual(code, 6, report)
        self.assertEqual(report['publication'], 'not-published')
        self.assertEqual(inventory(self.output), {'belongs-to-other-writer': __import__('hashlib').sha256(b'preserve').hexdigest()})
        self.assertEqual(before, inventory(self.source))

    def test_source_helpers_never_run_and_native_calls_use_owned_staging(self):
        import subprocess
        from historycrate.native import NativeAdapter
        marker = self.root / 'helper-invoked'
        trap = self.root / 'trap'
        trap.write_text('#!/bin/sh\nprintf invoked > "' + str(marker) + '"\nexit 93\n')
        trap.chmod(0o700)
        self.assertEqual(subprocess.run([str(trap)], check=False).returncode, 93)
        self.assertTrue(marker.exists())
        marker.unlink()
        config = self.source / 'config'
        config.write_text(config.read_text() + '\n[core]\n hooksPath = ' + str(self.root) + '\n fsmonitor = ' + str(trap)
                          + '\n pager = ' + str(trap) + '\n[credential]\n helper = !' + str(trap)
                          + '\n[filter "lfs"]\n process = ' + str(trap) + '\n[remote "origin"]\n url = trap::fixture\n')
        # A supported-history inspection must never ask a transport helper.
        before = inventory(self.source)
        calls = []
        execute = NativeAdapter._execute
        def record(adapter, args, cwd, *positional, **kwargs):
            cwd = Path(cwd)
            self.assertTrue(cwd == adapter.root or adapter.root in cwd.parents)
            self.assertFalse(cwd == self.source or self.source in cwd.parents)
            self.assertFalse(any(part in ('fetch', 'clone', 'pull') for part in args))
            calls.append(cwd)
            return execute(adapter, args, cwd, *positional, **kwargs)
        with patch('historycrate.cli.doctor', return_value={'status': 'passed'}), patch.object(NativeAdapter, '_execute', record):
            code, report, _ = self.pack()
        self.assertEqual(code, 0, report)
        self.assertTrue(calls)
        self.assertFalse(marker.exists())
        self.assertEqual(before, inventory(self.source))
