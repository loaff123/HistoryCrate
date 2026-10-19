"""Process lifecycle contract; all subprocess inputs are tiny owned fixtures."""
import importlib
import io
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import time
import unittest
from unittest import mock

FIXTURE = Path(__file__).parent / 'fixtures' / 'process_fixture.py'
ROOT = Path(__file__).parents[1]


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT / 'src/historycrate/process.py').is_file(),
                        'bounded process lifecycle is not implemented')
        self.module = importlib.import_module('historycrate.process')
        self.Limits = importlib.import_module('historycrate.limits').Limits
        self.CrateError = importlib.import_module('historycrate.errors').CrateError
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_fixture(self, *args, limits=None, stdin=b'', sink=None, scratch=None):
        return self.module.run_process((sys.executable, str(FIXTURE), *map(str, args)),
            self.root, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
            limits or self.Limits(), stdin, sink=sink, scratch=scratch)

    def test_stdin_stdout_stderr_and_observations(self):
        result = self.run_fixture('echo', stdin=b'hello\x00world')
        self.assertEqual(result.stdout, b'hello\x00world')
        self.assertEqual(result.stderr, b'fixture stderr')
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.observations['samples'])
        self.assertIn('sampled', result.observations['rss_kind'])
        self.assertTrue(result.observations['cleanup']['direct_child_reaped'])

    def test_nonzero_is_reported_without_success_fabrication(self):
        self.assertEqual(self.run_fixture('exit', 7).returncode, 7)

    def test_captured_output_overflow_aborts(self):
        for stream in ('stdout', 'stderr'):
            with self.subTest(stream=stream):
                with self.assertRaises(self.CrateError) as raised:
                    self.run_fixture('output', stream, 8192,
                        limits=self.Limits().lower({'captured_bytes': 1024}))
                self.assertEqual(raised.exception.exit_code, 5)
                self.assertEqual(raised.exception.context['resource'], stream)
                self.assertTrue(raised.exception.context['observations']['cleanup']['direct_child_reaped'])

    def test_stream_avoids_capture_limit_but_enforces_object_limit(self):
        sink = io.BytesIO()
        limits = self.Limits().lower({'captured_bytes': 1024, 'git_object_bytes': 4096})
        result = self.run_fixture('output', 'stdout', 2048, limits=limits, sink=sink)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(sink.getvalue(), b'x' * 2048)
        with self.assertRaises(self.CrateError):
            self.run_fixture('output', 'stdout', 8192, limits=limits, sink=io.BytesIO())

    def test_stdin_is_bounded_before_launch(self):
        with self.assertRaises(self.CrateError) as raised:
            self.run_fixture('echo', stdin=b'x' * 33,
                limits=self.Limits().lower({'git_object_bytes': 32}))
        self.assertEqual(raised.exception.context['resource'], 'stdin')

    def test_timeout_kills_and_reaps_expected_process_group(self):
        pid_file = self.root / 'pid'
        start = time.monotonic()
        with self.assertRaises(self.CrateError) as raised:
            self.run_fixture('ignore-term', pid_file,
                limits=self.Limits().lower({'command_wall_seconds': 1}))
        self.assertLess(time.monotonic() - start, 4)
        self.assertEqual(raised.exception.exit_code, 5)
        cleanup = raised.exception.context['observations']['cleanup']
        self.assertTrue(cleanup['direct_child_reaped'])
        self.assertTrue(cleanup['kill_sent'])
        self.assertFalse(cleanup['uncertain'])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    def test_rlimits_are_per_process_and_address_space_is_unchanged(self):
        before = {name: resource.getrlimit(getattr(resource, name)) for name in
            ('RLIMIT_CPU', 'RLIMIT_FSIZE', 'RLIMIT_NOFILE', 'RLIMIT_AS')}
        limits = self.Limits().lower({'command_cpu_seconds': 2, 'command_file_bytes': 1048576,
                                    'command_descriptors': 64})
        result = self.run_fixture('limits', limits=limits)
        actual = json.loads(result.stdout)
        self.assertEqual(actual['RLIMIT_AS'], list(before['RLIMIT_AS']))
        for name, bound in [('RLIMIT_CPU', 2), ('RLIMIT_FSIZE', 1048576), ('RLIMIT_NOFILE', 64)]:
            self.assertLessEqual(actual[name][0], bound)
            self.assertLessEqual(actual[name][1], bound)
            for inherited, imposed in zip(before[name], actual[name]):
                if inherited != resource.RLIM_INFINITY:
                    self.assertLessEqual(imposed, inherited)
        for name in before:
            self.assertEqual(resource.getrlimit(getattr(resource, name)), before[name])
        self.assertEqual(result.observations['rlimits']['RLIMIT_AS']['applied'], list(before['RLIMIT_AS']))

    def test_observed_rss_abort_includes_thread_descendant(self):
        # 96 MiB stays small while comfortably exceeding a 64 MiB threshold.
        pid_file = self.root / 'descendant'
        with self.assertRaises(self.CrateError) as raised:
            self.run_fixture('family', 96 * 1024 * 1024, pid_file,
                limits=self.Limits().lower({'observed_rss_bytes': 64 * 1024 * 1024,
                                         'command_wall_seconds': 5}))
        self.assertEqual(raised.exception.context['resource'], 'observed_rss_bytes')
        pid = int(pid_file.read_text())
        processes = raised.exception.context['observations']['processes']
        samples = [item for item in processes if item['pid'] == pid]
        self.assertEqual(len(samples), 1)
        self.assertGreater(samples[0]['max_rss_bytes'], 64 * 1024 * 1024)
        self.assertEqual(samples[0]['role'], 'descendant')

    def test_sample_gaps_starttime_and_approximation_are_reported(self):
        result = self.run_fixture('scratch', self.root / 'tiny', 8, 1.15)
        observations = result.observations
        self.assertGreaterEqual(len(observations['samples']), 2)
        self.assertGreater(observations['max_sample_gap_seconds'], 0)
        self.assertTrue(all(item['starttime'] > 0 for item in observations['processes']))
        self.assertTrue(observations['limitations'])

    def test_observation_entry_limit_blocks(self):
        with self.assertRaises(self.CrateError) as raised:
            self.run_fixture('sleep', limits=self.Limits().lower({'observation_entries': 1}))
        self.assertEqual(raised.exception.context['resource'], 'observation_entries')

    def test_scratch_sample_excess_aborts_after_command(self):
        with self.assertRaises(self.CrateError) as raised:
            self.run_fixture('scratch', self.root / 'data', 2048, 0,
                limits=self.Limits().lower({'scratch_bytes': 1024}), scratch=self.root)
        self.assertEqual(raised.exception.context['resource'], 'scratch_bytes')
        obs = raised.exception.context['observations']
        self.assertGreaterEqual(obs['max_scratch_bytes'], 2048)
        self.assertIn('observed', obs['scratch_kind'])

    def test_scratch_observation_does_not_follow_symlinks(self):
        elsewhere = self.root / 'elsewhere'
        elsewhere.mkdir()
        (elsewhere / 'large').write_bytes(b'x' * 4096)
        scratch = self.root / 'scratch'
        scratch.mkdir()
        (scratch / 'link').symlink_to(elsewhere, target_is_directory=True)
        result = self.run_fixture('exit', 0,
            limits=self.Limits().lower({'scratch_bytes': 32}), scratch=scratch)
        self.assertEqual(result.observations['max_scratch_bytes'], 0)

    def test_absent_children_capability_uses_reported_bounded_fallback(self):
        real_read = self.module._bounded_read
        def missing_children(path):
            if path.name == 'children':
                raise FileNotFoundError(path)
            return real_read(path)
        with mock.patch.object(self.module, '_bounded_read', side_effect=missing_children):
            result = self.run_fixture('echo', stdin=b'fallback')
        self.assertEqual(result.stdout, b'fallback')
        self.assertEqual(result.observations['descendant_discovery_method'], 'bounded-procfs-ppid-session')
        self.assertIn('children', result.observations['discovery_reason'])

    def test_denied_children_capability_never_uses_fallback(self):
        real_read = self.module._bounded_read
        def denied_children(path):
            if path.name == 'children':
                raise PermissionError(13, 'fixture denied')
            return real_read(path)
        with mock.patch.object(self.module, '_bounded_read', side_effect=denied_children):
            with self.assertRaises(self.CrateError) as raised:
                self.run_fixture('sleep')
        self.assertEqual(raised.exception.code, 'OBSERVATION_UNREADABLE')
        self.assertTrue(raised.exception.context['observations']['cleanup']['direct_child_reaped'])

    def test_fallback_ignores_unrelated_process_status_permissions(self):
        real_read = self.module._bounded_read
        def selective_read(path):
            if path.name == 'children':
                raise FileNotFoundError(path)
            if path == Path('/proc/1/status') and os.getpid() != 1:
                raise PermissionError(13, 'unrelated process status denied')
            return real_read(path)
        with mock.patch.object(self.module, '_bounded_read', side_effect=selective_read):
            self.assertEqual(self.run_fixture('echo', stdin=b'owned').stdout, b'owned')

    def test_fallback_unclassifiable_live_process_fails_closed(self):
        real_read = self.module._bounded_read
        def selective_read(path):
            if path.name == 'children':
                raise FileNotFoundError(path)
            if path == Path('/proc/1/stat'):
                raise PermissionError(13, 'cannot classify live process')
            return real_read(path)
        with mock.patch.object(self.module, '_bounded_read', side_effect=selective_read):
            with self.assertRaises(self.CrateError) as raised:
                self.run_fixture('sleep')
        self.assertEqual(raised.exception.code, 'OBSERVATION_UNREADABLE')

    def test_pid_reuse_is_rejected_before_sampling(self):
        observer = self.module._Observer(self.Limits(), time.monotonic(), time.monotonic() + 5, None)
        with mock.patch.object(self.module, '_identity', side_effect=[(111, 'S', 10, 10), (222, 'S', 10, 10)]):
            self.assertIsNotNone(observer._pin(10, 'direct'))
            self.assertIsNone(observer._pin(10, 'direct'))
        self.assertEqual(observer.known[10]['starttime'], 111)
        self.assertTrue(observer.known[10]['pid_reused'])

    def test_fallback_requires_owned_session_and_group_or_parent_chain(self):
        observer = self.module._Observer(self.Limits(), time.monotonic(), time.monotonic() + 5, None)
        observer.direct_pid = 10
        observer.known[10] = {'pid': 10, 'starttime': 100, 'role': 'direct', 'exited': False}
        # (starttime, state, pgrp, session, ppid). PID 13 is unrelated despite
        # matching group; 14 is unrelated despite matching session. PID 15 is
        # a descendant across a newly created session, still observable by PPid.
        snapshot = {10: (100, 'S', 10, 10, 1), 11: (101, 'S', 10, 10, 10),
                    12: (102, 'S', 10, 10, 1), 13: (103, 'S', 10, 999, 1),
                    14: (104, 'S', 999, 10, 1), 15: (105, 'S', 15, 15, 11)}
        self.assertTrue(hasattr(observer, '_select_owned_snapshot'), 'fallback ownership selection is missing')
        with mock.patch.object(self.module, '_identity', side_effect=lambda pid: snapshot[pid][:4]):
            self.assertEqual(observer._select_owned_snapshot(snapshot), {10, 11, 12, 15})
            observer.known[10]['starttime'] = 999
            self.assertEqual(observer._select_owned_snapshot(snapshot), set())

    def test_only_internal_framed_sink_gets_bounded_header_allowance(self):
        class FramedSink(io.BytesIO):
            framing_overhead = 202
        limits = self.Limits().lower({'git_object_bytes': 32})
        sink = FramedSink()
        result = self.run_fixture('output', 'stdout', 234, limits=limits, sink=sink)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(len(sink.getvalue()), 234)
        with self.assertRaises(self.CrateError):
            self.run_fixture('output', 'stdout', 235, limits=limits, sink=FramedSink())
        with self.assertRaises(self.CrateError):
            self.run_fixture('output', 'stdout', 33, limits=limits, sink=io.BytesIO())

    def test_failures_expose_top_level_cleanup_uncertainty(self):
        with self.assertRaises(self.CrateError) as raised:
            self.run_fixture('output', 'stdout', 4096,
                             limits=self.Limits().lower({'captured_bytes': 16}))
        self.assertFalse(raised.exception.context['cleanup_uncertain'])

    def test_unreadable_procfs_still_terminates_unreaped_direct_child(self):
        real_popen = self.module.subprocess.Popen
        real_identity = self.module._identity
        launched = []
        def launch(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            launched.append(process)
            return process
        seen = set()
        def identity(pid):
            if launched and pid == launched[0].pid:
                if pid in seen:
                    raise self.CrateError('OBSERVATION_UNREADABLE', 5, {'resource': 'procfs'})
                seen.add(pid)
            return real_identity(pid)
        try:
            with mock.patch.object(self.module.subprocess, 'Popen', side_effect=launch), \
                    mock.patch.object(self.module, '_identity', side_effect=identity):
                with self.assertRaises(self.CrateError) as raised:
                    self.run_fixture('sleep')
            self.assertIsNotNone(launched[0].poll(), 'owned direct child was left running')
            self.assertTrue(raised.exception.context['observations']['cleanup']['direct_child_reaped'])
        finally:
            if launched and launched[0].poll() is None:
                import signal
                os.killpg(launched[0].pid, signal.SIGKILL)
                launched[0].wait()

    def test_snapshot_identity_change_prevents_new_process_observation(self):
        observer = self.module._Observer(self.Limits(), time.monotonic(), time.monotonic() + 5, None)
        with mock.patch.object(self.module, '_identity', return_value=(222, 'S', 99, 99)):
            self.assertIsNone(observer._pin(10, 'descendant', expected_starttime=111))
        self.assertNotIn(10, observer.known)

    def test_whole_job_deadline_interrupts_longer_command_limit(self):
        start = time.monotonic()
        with self.assertRaises(self.CrateError) as raised:
            self.module.run_process((sys.executable, str(FIXTURE), 'sleep'), self.root, {},
                self.Limits(), absolute_deadline=start + .2)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(raised.exception.context['resource'], 'job_wall_seconds')
        self.assertTrue(raised.exception.context['observations']['cleanup']['direct_child_reaped'])

    def test_expired_job_deadline_does_not_launch(self):
        path = self.root / 'must-not-exist'
        with self.assertRaises(self.CrateError) as raised:
            self.module.run_process((sys.executable, str(FIXTURE), 'scratch', str(path), '1', '0'),
                self.root, {}, self.Limits(), absolute_deadline=time.monotonic() - 1)
        self.assertEqual(raised.exception.context['resource'], 'job_wall_seconds')
        self.assertFalse(path.exists())

    def test_all_thread_children_path_discovers_non_main_thread_child(self):
        pid_file = self.root / 'descendant'
        real_read = self.module._bounded_read
        def children_backend(path):
            if path.name != 'children':
                return real_read(path)
            # Only emulate the unavailable children interface. All process
            # creation, identities, RSS, limits and cleanup remain real.
            pid, tid = int(path.parts[2]), int(path.parts[4])
            if pid != os.getpid() and tid != pid and pid_file.exists():
                return pid_file.read_bytes()
            return b''
        with mock.patch.object(self.module, '_bounded_read', side_effect=children_backend):
            with self.assertRaises(self.CrateError) as raised:
                self.run_fixture('family', 96 * 1024 * 1024, pid_file,
                    limits=self.Limits().lower({'observed_rss_bytes': 64 * 1024 * 1024,
                                               'command_wall_seconds': 5}))
        self.assertEqual(raised.exception.context['resource'], 'observed_rss_bytes')
        self.assertEqual(raised.exception.context['observations']['descendant_discovery_method'],
                         'all-thread-children')

    def test_inherited_low_limits_are_not_raised_in_native_child(self):
        result = self.run_fixture('limited-parent', ROOT / 'src')
        self.assertEqual(result.returncode, 0, result.stderr)
        inherited = json.loads(result.stdout)
        self.assertEqual(inherited['RLIMIT_CPU'], [1, 1])
        self.assertEqual(inherited['RLIMIT_FSIZE'], [1048576, 1048576])
        self.assertEqual(inherited['RLIMIT_NOFILE'], [32, 32])
        self.assertEqual(inherited['RLIMIT_AS'], [256 * 1024 * 1024, 256 * 1024 * 1024])

    def test_framed_control_stdin_has_only_exact_oid_line_exception(self):
        class FramedSink(io.BytesIO):
            framing_overhead = 202
        limits = self.Limits().lower({'git_object_bytes': 8})
        control = b'a' * 40 + b'\n'
        sink = FramedSink()
        self.run_fixture('echo', stdin=control, sink=sink, limits=limits)
        self.assertEqual(sink.getvalue(), control)
        for invalid in (b'A' * 40 + b'\n', b'a' * 41, b'a' * 41 + b'\n'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(self.CrateError):
                    self.run_fixture('echo', stdin=invalid, sink=FramedSink(), limits=limits)
        with self.assertRaises(self.CrateError):
            self.run_fixture('echo', stdin=control, sink=io.BytesIO(), limits=limits)

    def test_fallback_discards_ppid_branch_when_parent_identity_changed(self):
        observer = self.module._Observer(self.Limits(), time.monotonic(), time.monotonic() + 5, None)
        observer.direct_pid = 10
        observer.known[10] = {'pid': 10, 'starttime': 100, 'role': 'direct', 'exited': False}
        snapshot = {10: (100, 'S', 10, 10, 1), 11: (101, 'S', 11, 11, 10),
                    12: (102, 'S', 12, 12, 11)}
        def current(pid):
            if pid == 11:
                return (999, 'S', 11, 11)  # Snapshot parent was reaped and PID reused.
            return snapshot[pid][:4]
        with mock.patch.object(self.module, '_identity', side_effect=current):
            self.assertEqual(observer._select_owned_snapshot(snapshot), {10})

    def test_cancellation_reports_130_after_reaping(self):
        with mock.patch.object(self.module._Observer, 'sample', side_effect=KeyboardInterrupt):
            with self.assertRaises(self.CrateError) as raised:
                self.run_fixture('sleep')
        self.assertEqual(raised.exception.exit_code, 130)
        self.assertTrue(raised.exception.context['observations']['cleanup']['direct_child_reaped'])
        self.assertFalse(raised.exception.context['cleanup_uncertain'])

    def test_system_exit_keeps_original_code_after_reaping(self):
        launched = []
        real_popen = self.module.subprocess.Popen
        def launch(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            launched.append(process)
            return process
        with mock.patch.object(self.module.subprocess, 'Popen', side_effect=launch), \
                mock.patch.object(self.module._Observer, 'sample', side_effect=SystemExit(17)):
            with self.assertRaises(SystemExit) as raised:
                self.run_fixture('sleep')
        self.assertEqual(raised.exception.code, 17)
        self.assertIsNotNone(launched[0].returncode)

    def test_internal_api_rejects_shell_string(self):
        with self.assertRaises(self.CrateError):
            self.module.run_process('echo unsafe', self.root, {}, self.Limits())


if __name__ == '__main__':
    unittest.main()
