"""Internal bounded subprocess lifecycle for the fixed-operation native adapter.

This is deliberately not a public arbitrary-command interface or an OS sandbox.
RSS and scratch observations are approximate abort thresholds, not hard quotas.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import resource
import selectors
import signal
import stat
import subprocess
import time
from typing import BinaryIO

from .errors import CrateError
from .limits import Limits

_READ_BOUND = 64 * 1024
_SAMPLE_SECONDS = 1.0
_LIMITATIONS = (
    'RSS is sampled and approximate; peaks between samples can be larger.',
    'Short-lived or reparented descendants may be missed; scheduling can delay observations.',
    'Per-process RLIMITs are not aggregate limits; scratch observations are not a filesystem quota.',
    'Owned process-group cleanup cannot guarantee termination of escaped descendants.',
)


@dataclass(frozen=True)
class ProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    observations: dict[str, object]


def _error(code: str, resource_name: str, **context: object) -> CrateError:
    return CrateError(code.upper(), 5, {'resource': resource_name, **context})


def _bounded_read(path: Path) -> bytes:
    with path.open('rb', buffering=0) as handle:
        data = handle.read(_READ_BOUND + 1)
    if len(data) > _READ_BOUND:
        raise _error('observation_metadata_limit', 'observation_metadata_bytes')
    return data


def _proc_record(pid: int) -> tuple[int, str, int, int, int] | None:
    """Read starttime, state, process group, session and parent PID; vanished processes are normal."""
    try:
        raw = _bounded_read(Path('/proc') / str(pid) / 'stat')
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as exc:
        raise _error('observation_unreadable', 'procfs', pid=pid, errno=exc.errno) from None
    try:
        fields = raw[raw.rindex(b')') + 2:].split()
        return int(fields[19]), fields[0].decode('ascii'), int(fields[2]), int(fields[3]), int(fields[1])
    except (ValueError, IndexError, UnicodeError):
        raise _error('observation_malformed', 'procfs', pid=pid) from None


def _identity(pid: int) -> tuple[int, str, int, int] | None:
    record = _proc_record(pid)
    return None if record is None else record[:4]


class _Observer:
    def __init__(self, limits: Limits, start: float, deadline: float, scratch: Path | None):
        self.limits = limits
        self.start = start
        self.deadline = deadline
        self.scratch = scratch
        self.known: dict[int, dict[str, object]] = {}
        self.samples: list[dict[str, object]] = []
        self.scratch_samples: list[dict[str, object]] = []
        self.rss_settling: list[dict[str, object]] = []
        self.max_gap = 0.0
        self.last_sample: float | None = None
        self.max_scratch = 0
        self.direct_pid: int | None = None
        self.entry_bound = min(4096, limits.observation_entries)
        self.entries = 0
        self.observation_deadline = deadline
        self.cleanup: dict[str, object] = {
            'direct_child_reaped': False, 'term_sent': False, 'kill_sent': False,
            'uncertain': False, 'limitations': _LIMITATIONS[-1],
        }
        self.rlimits: dict[str, object] = {}
        self.discovery_method: str | None = None
        self.discovery_reason: str | None = None

    def report(self) -> dict[str, object]:
        return {
            'rss_kind': 'sampled approximate per-process abort threshold',
            'scratch_kind': 'observed regular-file byte abort threshold; not a hard quota',
            'samples': self.samples, 'max_sample_gap_seconds': self.max_gap,
            'processes': list(self.known.values()), 'scratch_samples': self.scratch_samples,
            'max_scratch_bytes': self.max_scratch, 'rlimits': self.rlimits,
            'cleanup': self.cleanup, 'limitations': list(_LIMITATIONS),
            'rss_settling': self.rss_settling,
            'descendant_discovery_method': self.discovery_method,
            'discovery_reason': self.discovery_reason,
        }

    def _tick(self) -> None:
        self.entries += 1
        if self.entries > self.entry_bound:
            raise _error('observation_entry_limit', 'observation_entries', limit=self.entry_bound)
        if time.monotonic() > self.observation_deadline:
            raise _error('observation_time_limit', 'observation_wall_seconds')

    def _pin(self, pid: int, role: str, expected_starttime: int | None = None) -> tuple[int, str, int, int] | None:
        ident = _identity(pid)
        if ident is None:
            if pid in self.known:
                self.known[pid]['exited'] = True
            return None
        if expected_starttime is not None and expected_starttime != ident[0]:
            return None  # PID changed after the bounded snapshot.
        if pid in self.known:
            if self.known[pid]['starttime'] != ident[0]:
                self.known[pid]['exited'] = True
                self.known[pid]['pid_reused'] = True
                return None
        else:
            if len(self.known) >= self.entry_bound:
                raise _error('observation_entry_limit', 'observation_entries', limit=self.entry_bound)
            self.known[pid] = {'pid': pid, 'starttime': ident[0], 'role': role,
                               'max_rss_bytes': 0, 'exited': False, 'pid_reused': False}
        if ident[1] in ('Z', 'X'):
            self.known[pid]['exited'] = True
        return ident

    def _choose_discovery(self) -> None:
        if self.discovery_method is not None:
            return
        pid = os.getpid()
        thread = Path('/proc') / str(pid) / 'task' / str(pid)
        try:
            _bounded_read(thread / 'children')
        except (FileNotFoundError, ProcessLookupError):
            # The controller's main thread cannot have exited here. Revalidate
            # its existence so ENOENT is a capability gap, never a denial bypass.
            try:
                os.stat(thread, follow_symlinks=False)
            except OSError as exc:
                raise _error('observation_unreadable', 'procfs', pid=pid, errno=exc.errno) from None
            self.discovery_method = 'bounded-procfs-ppid-session'
            self.discovery_reason = 'live controller thread children file absent; approved bounded stat fallback'
        except OSError as exc:
            raise _error('observation_unreadable', 'procfs', pid=pid, errno=exc.errno) from None
        else:
            self.discovery_method = 'all-thread-children'
            self.discovery_reason = 'live controller thread children file readable'

    def _select_owned_snapshot(self, snapshot: dict[int, tuple]) -> set[int]:
        # Parent-PID snapshots are non-atomic. Keep the proof chain for each
        # inferred descendant and revalidate every ancestor's pinned starttime
        # before admitting a PPid-only child, then recheck before returning.
        parents: dict[int, int | None] = {}

        def current(pid: int) -> tuple | None:
            self._tick()
            identity = _identity(pid)
            if identity is None or identity[0] != snapshot[pid][0]:
                return None
            return identity

        def valid_path(pid: int) -> bool:
            visited: set[int] = set()
            while pid is not None:
                if pid in visited or current(pid) is None:
                    return False
                visited.add(pid)
                pid = parents[pid]
            return True

        for pid, record in snapshot.items():
            if (pid in self.known and self.known[pid]['role'] != 'controller' and
                    self.known[pid]['starttime'] == record[0] and current(pid) is not None):
                parents[pid] = None
        group_anchors = [pid for pid in parents if snapshot[pid][2] == self.direct_pid
                         and snapshot[pid][3] == self.direct_pid]
        if group_anchors:
            anchor = group_anchors[0]
            for pid, record in snapshot.items():
                if pid in parents or record[2:4] != (self.direct_pid, self.direct_pid):
                    continue
                identity = current(pid)
                if identity is not None and identity[2:4] == record[2:4] and valid_path(anchor):
                    parents[pid] = anchor
        changed = True
        while changed:
            old_size = len(parents)
            for pid, record in snapshot.items():
                if pid not in parents and record[4] in parents:
                    if valid_path(record[4]) and current(pid) is not None:
                        parents[pid] = record[4]
            changed = len(parents) != old_size
        return {pid for pid in parents if valid_path(pid)}

    def _fallback_snapshot(self) -> dict[int, tuple]:
        snapshot: dict[int, tuple] = {}
        try:
            with os.scandir('/proc') as entries:
                for entry in entries:
                    self._tick()
                    if not entry.name.isdecimal():
                        continue
                    pid = int(entry.name)
                    # Read only stat for classification. An unrelated process's
                    # status may legitimately be unreadable and is never read.
                    # Unreadable live stat cannot be safely classified: block.
                    record = _proc_record(pid)
                    if record is not None:
                        snapshot[pid] = record
        except OSError as exc:
            raise _error('observation_unreadable', 'procfs', errno=exc.errno) from None
        return {pid: snapshot[pid] for pid in self._select_owned_snapshot(snapshot)}

    def sample(self) -> None:
        now = time.monotonic()
        gap = None if self.last_sample is None else now - self.last_sample
        if gap is not None:
            self.max_gap = max(self.max_gap, gap)
        self.last_sample = now
        sample: dict[str, object] = {
            'elapsed_seconds': now - self.start,
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'gap_seconds': gap, 'rss_bytes': {},
        }
        self.samples.append(sample)
        self.entries = 0
        self.observation_deadline = min(self.deadline, now + 1.0)
        self._choose_discovery()
        snapshot = self._fallback_snapshot() if self.discovery_method == 'bounded-procfs-ppid-session' else {}
        queue = [(os.getpid(), 'controller')]
        queue += [(pid, 'descendant') for pid in snapshot if pid != self.direct_pid]
        if self.direct_pid is not None:
            queue.append((self.direct_pid, 'direct'))
        queue += [(pid, 'descendant') for pid, item in self.known.items()
                  if item['role'] == 'descendant' and not item['exited']]
        visited: set[int] = set()
        while queue:
            pid, role = queue.pop()
            if pid in visited:
                continue
            visited.add(pid)
            self._tick()
            ident = self._pin(pid, role, snapshot[pid][0] if pid in snapshot else None)
            if ident is None or ident[1] in ('Z', 'X'):
                continue
            root = Path('/proc') / str(pid)
            try:
                status = _bounded_read(root / 'status')
                rss_lines = [line.split() for line in status.splitlines() if line.startswith(b'VmRSS:')]
                if not rss_lines:
                    # During exit_mm(), Linux may briefly expose a complete
                    # running status without memory fields before Z/ENOENT.
                    # Absence is not an RSS=0 or exit claim: settle only until
                    # identity-pinned terminal evidence or a valid RSS frame.
                    settlement={'pid':pid,'starttime':ident[0],'checks':0,'outcome':'unconfirmed'}
                    self.rss_settling.append(settlement)
                    settle_deadline=min(self.observation_deadline,time.monotonic()+0.050)
                    exited=False
                    while not rss_lines:
                        self._tick();settlement['checks']+=1
                        current=_identity(pid)
                        if current is None or current[0]!=ident[0] or current[1] in ('Z','X'):
                            self.known[pid]['exited']=True
                            if current is not None and current[0]!=ident[0]:self.known[pid]['pid_reused']=True
                            settlement['outcome']='identity-replaced' if current is not None and current[0]!=ident[0] else 'confirmed-exit'
                            exited=True;break
                        remaining=settle_deadline-time.monotonic()
                        if remaining<=0:
                            settlement['outcome']='live-missing-rss-refused'
                            raise _error('observation_malformed','procfs',pid=pid)
                        time.sleep(min(0.001,remaining))
                        self._tick()
                        status=_bounded_read(root/'status')
                        rss_lines=[line.split() for line in status.splitlines() if line.startswith(b'VmRSS:')]
                    if exited:continue
                    settlement['outcome']='rss-restored'
                if len(rss_lines) != 1 or len(rss_lines[0]) != 3 or rss_lines[0][2] != b'kB':
                    raise _error('observation_malformed', 'procfs', pid=pid)
                rss = int(rss_lines[0][1]) * 1024
                if rss < 0:
                    raise ValueError('negative RSS')
                children: set[int] = set()
                # Do not walk unrelated controller children; only the direct
                # command and its already discovered family are owned here.
                if role != 'controller' and self.discovery_method == 'all-thread-children':
                    with os.scandir(root / 'task') as tasks:
                        for task in tasks:
                            self._tick()
                            if not task.name.isdecimal():
                                continue
                            try:
                                raw = _bounded_read(Path(task.path) / 'children')
                            except (FileNotFoundError, ProcessLookupError):
                                # Missing children on a still-existing thread is
                                # unsupported procfs, not evidence of no children.
                                try:
                                    os.stat(task.path, follow_symlinks=False)
                                except (FileNotFoundError, ProcessLookupError):
                                    continue
                                raise _error('observation_unreadable', 'procfs', pid=pid,
                                             tid=int(task.name), detail='live thread children list unavailable') from None
                            for number in raw.split():
                                child = int(number)
                                if child <= 0:
                                    raise ValueError('invalid child PID')
                                children.add(child)
                                if len(children) > self.entry_bound:
                                    raise _error('observation_entry_limit', 'observation_entries')
                current = _identity(pid)
                if current is None or current[0] != ident[0]:
                    self.known[pid]['exited'] = True
                    continue
                sample['rss_bytes'][str(pid)] = rss
                self.known[pid]['max_rss_bytes'] = max(self.known[pid]['max_rss_bytes'], rss)
                if rss > self.limits.observed_rss_bytes:
                    raise _error('observed_rss_limit', 'observed_rss_bytes', pid=pid,
                                 observed=rss, limit=self.limits.observed_rss_bytes)
                queue.extend((child, 'descendant') for child in children)
            except (FileNotFoundError, ProcessLookupError):
                current = _identity(pid)
                if current is not None and current[0] == ident[0] and current[1] not in ('Z', 'X'):
                    raise _error('observation_unreadable', 'procfs', pid=pid) from None
                self.known[pid]['exited'] = True
            except OSError as exc:
                current = _identity(pid)
                if current is not None and current[0] == ident[0] and current[1] not in ('Z', 'X'):
                    raise _error('observation_unreadable', 'procfs', pid=pid, errno=exc.errno) from None
                self.known[pid]['exited'] = True
            except ValueError:
                raise _error('observation_malformed', 'procfs', pid=pid) from None
        sample['entries'] = self.entries

    def sample_scratch(self) -> None:
        if self.scratch is None:
            return
        now = time.monotonic()
        total, entries = 0, 0
        deadline = min(self.deadline, now + 1.0)
        # Open each directory relative to its pinned parent, without following
        # symlinks, so replacement cannot redirect the observer outside scratch.
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        descriptors: list[int] = []
        try:
            descriptors.append(os.open(self.scratch, flags))
            while descriptors:
                fd = descriptors.pop()
                try:
                    with os.scandir(fd) as items:
                        for item in items:
                            entries += 1
                            if entries > self.entry_bound:
                                raise _error('observation_entry_limit', 'observation_entries')
                            if time.monotonic() > deadline:
                                raise _error('observation_time_limit', 'observation_wall_seconds')
                            try:
                                info = os.stat(item.name, dir_fd=fd, follow_symlinks=False)
                                if stat.S_ISREG(info.st_mode):
                                    total += info.st_size
                                elif stat.S_ISDIR(info.st_mode):
                                    descriptors.append(os.open(item.name, flags, dir_fd=fd))
                            except FileNotFoundError:
                                continue  # Native temporary files can disappear normally.
                finally:
                    os.close(fd)
        except OSError as exc:
            raise _error('scratch_observation_failed', 'scratch_bytes', errno=exc.errno) from None
        finally:
            for fd in descriptors:
                os.close(fd)
        self.max_scratch = max(self.max_scratch, total)
        self.scratch_samples.append({'elapsed_seconds': now - self.start,
                                     'observed_bytes': total, 'entries': entries})
        if total > self.limits.scratch_bytes:
            raise _error('observed_scratch_limit', 'scratch_bytes', observed=total,
                         limit=self.limits.scratch_bytes)


def _rlimits(limits: Limits) -> tuple[dict[int, tuple[int, int]], dict[str, object]]:
    changes: dict[int, tuple[int, int]] = {}
    report: dict[str, object] = {}
    for name, bound in [('RLIMIT_CPU', limits.command_cpu_seconds),
                        ('RLIMIT_FSIZE', limits.command_file_bytes),
                        ('RLIMIT_NOFILE', limits.command_descriptors), ('RLIMIT_AS', None)]:
        key = getattr(resource, name)
        inherited = resource.getrlimit(key)
        applied = inherited if bound is None else tuple(
            bound if value == resource.RLIM_INFINITY else min(value, bound) for value in inherited)
        if bound is not None:
            changes[key] = applied
        report[name] = {'inherited': list(inherited), 'applied': list(applied),
                        'kind': 'inherited unchanged' if bound is None else 'per-process enforced'}
    return changes, report


def _live_members(observer: _Observer) -> list[tuple[int, tuple[int, str, int, int]]]:
    live = []
    for pid, item in observer.known.items():
        if item['role'] == 'controller':
            continue
        ident = _identity(pid)
        if ident is not None and ident[0] == item['starttime'] and ident[1] not in ('Z', 'X'):
            live.append((pid, ident))
        else:
            item['exited'] = True
    return live


def _cleanup(process: subprocess.Popen, observer: _Observer, abort: bool) -> None:
    """Signal only the owned group, then reap the one directly launched child."""
    def members() -> list[tuple[int, tuple[int, str, int, int]]]:
        try:
            return _live_members(observer)
        except (OSError, CrateError) as exc:
            observer.cleanup['uncertain'] = True
            observer.cleanup['observation_error'] = getattr(exc, 'code', 'cleanup_os_error')
            return []

    def signal_owned(sig: int) -> bool:
        # An unreaped direct child cannot have its PID reused. It was launched
        # as this session/group leader, so procfs failure must not prevent its
        # termination. Once reaped, require a still-live pinned group member.
        owned = process.poll() is None
        if not owned:
            owned = any(ident[2] == process.pid and ident[3] == process.pid
                        for _, ident in members())
        if not owned:
            return False
        try:
            os.killpg(process.pid, sig)
            return True
        except ProcessLookupError:
            return False
        except OSError as exc:
            observer.cleanup['uncertain'] = True
            observer.cleanup['signal_errno'] = exc.errno
            return False

    if abort or members():
        observer.cleanup['term_sent'] = signal_owned(signal.SIGTERM)
        end = time.monotonic() + 0.2
        while time.monotonic() < end:
            if process.poll() is not None and not members():
                break
            time.sleep(0.01)
        observer.cleanup['kill_sent'] = signal_owned(signal.SIGKILL)
    try:
        process.wait(timeout=1.0)
        observer.cleanup['direct_child_reaped'] = True
    except subprocess.TimeoutExpired:
        observer.cleanup['uncertain'] = True
    end = time.monotonic() + 0.3
    while members() and time.monotonic() < end:
        time.sleep(0.01)
    observer.cleanup['uncertain'] = observer.cleanup['uncertain'] or bool(members())


def run_process(argv: tuple[str, ...], cwd: Path, env: dict, limits: Limits,
                stdin: bytes = b'', *, sink: BinaryIO | None = None,
                scratch: Path | None = None, absolute_deadline: float | None = None,
                converted_output_limit: int | None = None, lfs_payload_input: bool = False) -> ProcessResult:
    """Run one fixed adapter operation. Never accept this API's argv from a CLI."""
    if (not isinstance(argv, tuple) or not argv or
            not all(isinstance(arg, str) and '\x00' not in arg for arg in argv) or
            not Path(argv[0]).is_absolute() or not isinstance(stdin, bytes)):
        raise _error('invalid_process_arguments', 'process_arguments')
    # Only the adapter's fixed parser requests this bounded framing allowance;
    # it independently enforces declared and actual payload bytes.
    framing_overhead = 202 if getattr(sink, 'framing_overhead', 0) == 202 else 0
    if converted_output_limit is not None:
        # Only the adapter's fixed ordinary-file checkout conversion uses this.
        # Supported text/eol expansion is at most two output bytes per blob byte.
        maximum=min(2*limits.git_object_bytes,limits.scratch_bytes,limits.command_file_bytes)
        if (sink is None or framing_overhead or type(converted_output_limit) is not int
                or not 0 <= converted_output_limit <= maximum):
            raise _error('invalid_process_arguments', 'converted_output_limit')
    stream_threshold=limits.git_object_bytes+framing_overhead if converted_output_limit is None else converted_output_limit
    stream_resource='git_object_bytes' if converted_output_limit is None else 'converted_file_bytes'
    framed_control = (framing_overhead == 202 and len(stdin) == 41 and stdin[-1:] == b'\n'
                      and all(value in b'0123456789abcdef' for value in stdin[:-1]))
    if type(lfs_payload_input) is not bool:
        raise _error('invalid_process_arguments','lfs_payload_input')
    input_threshold=limits.lfs_payload_bytes if lfs_payload_input else limits.git_object_bytes
    if len(stdin) > input_threshold and not (framed_control and not lfs_payload_input):
        raise _error('input_limit', 'lfs_payload_bytes' if lfs_payload_input else 'stdin', limit=input_threshold)
    start = time.monotonic()
    deadline = start + limits.command_wall_seconds
    timeout_resource = 'command_wall_seconds'
    if absolute_deadline is not None:
        if type(absolute_deadline) not in (int, float) or not math.isfinite(absolute_deadline):
            raise _error('invalid_process_arguments', 'absolute_deadline')
        if absolute_deadline <= deadline:
            deadline = absolute_deadline
            timeout_resource = 'job_wall_seconds'
    if start >= deadline:
        raise _error('command_timeout', timeout_resource)
    observer = _Observer(limits, start, deadline, scratch)
    changes, observer.rlimits = _rlimits(limits)

    def impose_limits() -> None:
        for key, value in changes.items():
            resource.setrlimit(key, value)

    process: subprocess.Popen | None = None
    selector = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    streamed = 0
    input_offset = 0
    failure: BaseException | None = None
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=dict(env), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
            start_new_session=True, preexec_fn=impose_limits, bufsize=0)
        observer.direct_pid = process.pid
        observer._pin(process.pid, 'direct')
        for name in ('stdout', 'stderr'):
            handle = getattr(process, name)
            os.set_blocking(handle.fileno(), False)
            selector.register(handle, selectors.EVENT_READ, name)
        if stdin:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
        else:
            process.stdin.close()
        next_sample = start
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if now >= deadline:
                raise _error('command_timeout', timeout_resource, limit=getattr(limits, timeout_resource))
            if now >= next_sample:
                observer.sample()
                observer.sample_scratch()
                next_sample = time.monotonic() + _SAMPLE_SECONDS
            for key, _ in selector.select(min(0.05, max(0.0, deadline - time.monotonic()))):
                handle, name = key.fileobj, key.data
                if name == 'stdin':
                    try:
                        written = os.write(handle.fileno(), memoryview(stdin)[input_offset:input_offset + _READ_BOUND])
                        input_offset += written
                    except BrokenPipeError:
                        input_offset = len(stdin)
                    except BlockingIOError:
                        continue
                    if input_offset == len(stdin):
                        selector.unregister(handle)
                        handle.close()
                    continue
                try:
                    chunk = os.read(handle.fileno(), _READ_BOUND)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(handle)
                    handle.close()
                    continue
                if name == 'stdout' and sink is not None:
                    streamed += len(chunk)
                    if streamed > stream_threshold:
                        raise _error('stream_output_limit', stream_resource, limit=stream_threshold)
                    remaining = memoryview(chunk)
                    while remaining:
                        written = sink.write(remaining)
                        if not isinstance(written, int) or written <= 0 or written > len(remaining):
                            raise _error('stream_write_failed', 'stdout')
                        remaining = remaining[written:]
                else:
                    if len(output[name]) + len(chunk) > limits.captured_bytes:
                        raise _error('captured_output_limit', name, limit=limits.captured_bytes)
                    output[name].extend(chunk)
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        observer.cleanup['direct_child_reaped'] = True
        observer.sample()
        observer.sample_scratch()  # Always observe after a command, even if short.
        if _live_members(observer):
            raise _error('native_descendants_remaining', 'process_cleanup')
    except BaseException as exc:
        failure = exc
    finally:
        selector.close()
        if process is not None:
            for name in ('stdin', 'stdout', 'stderr'):
                handle = getattr(process, name)
                if handle is not None and not handle.closed:
                    handle.close()
            _cleanup(process, observer, abort=failure is not None)
    report = observer.report()
    if failure is not None:
        if isinstance(failure, CrateError):
            raise CrateError(failure.code, failure.exit_code,
                             {**failure.context, 'observations': report,
                              'cleanup_uncertain': observer.cleanup['uncertain']}) from None
        if isinstance(failure, KeyboardInterrupt):
            raise CrateError('COMMAND_CANCELLED', 130, {'observations': report, 'cleanup_uncertain': observer.cleanup['uncertain']}) from None
        if isinstance(failure, SystemExit):
            if observer.cleanup['uncertain']:
                raise CrateError('CLEANUP_UNCERTAIN', 6,
                                 {'observations': report, 'cleanup_uncertain': True}) from None
            raise failure
        raise CrateError('PROCESS_IO_FAILED', 5,
                         {'errno': getattr(failure, 'errno', None), 'observations': report,
                          'cleanup_uncertain': observer.cleanup['uncertain']}) from None
    if observer.cleanup['uncertain']:
        raise CrateError('CLEANUP_UNCERTAIN', 5, {'observations': report, 'cleanup_uncertain': observer.cleanup['uncertain']})
    assert process is not None and process.returncode is not None
    return ProcessResult(bytes(output['stdout']), bytes(output['stderr']), process.returncode, report)
