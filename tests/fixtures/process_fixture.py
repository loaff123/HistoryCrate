"""Small original cooperative process fixtures (MIT). No native Git operations."""
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import threading
import time

mode = sys.argv[1]
if mode == 'echo':
    sys.stdout.buffer.write(sys.stdin.buffer.read())
    sys.stderr.buffer.write(b'fixture stderr')
elif mode == 'output':
    stream = sys.stdout.buffer if sys.argv[2] == 'stdout' else sys.stderr.buffer
    stream.write(b'x' * int(sys.argv[3]))
    stream.flush()
elif mode == 'limits':
    print(json.dumps({name: resource.getrlimit(getattr(resource, name)) for name in
        ('RLIMIT_CPU', 'RLIMIT_FSIZE', 'RLIMIT_NOFILE', 'RLIMIT_AS')}))
elif mode == 'sleep':
    time.sleep(30)
elif mode == 'family':
    # The descendant is launched by a non-main thread, so task/PID/children alone
    # is insufficient to discover it. All processes remain in the owned group.
    def launch():
        child = subprocess.Popen((sys.executable, __file__, 'allocate', sys.argv[2]))
        Path(sys.argv[3]).write_text(str(child.pid))
        child.wait()
    worker = threading.Thread(target=launch)
    worker.start()
    worker.join()
elif mode == 'allocate':
    payload = bytearray(int(sys.argv[2]))
    for offset in range(0, len(payload), 4096):
        payload[offset] = 1
    time.sleep(30)
elif mode == 'ignore-term':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(sys.argv[2]).write_text(str(os.getpid()))
    time.sleep(30)
elif mode == 'scratch':
    Path(sys.argv[2]).write_bytes(b'x' * int(sys.argv[3]))
    time.sleep(float(sys.argv[4]))
elif mode == 'limited-parent':
    # Limits affect only this disposable fixture and its child, never the test
    # controller or host settings. Use finite AS solely to test preservation.
    for name, value in [('RLIMIT_CPU', 1), ('RLIMIT_FSIZE', 1048576),
                        ('RLIMIT_NOFILE', 32), ('RLIMIT_AS', 256 * 1024 * 1024)]:
        resource.setrlimit(getattr(resource, name), (value, value))
    sys.path.insert(0, sys.argv[2])
    from historycrate.process import run_process
    from historycrate.limits import Limits
    result = run_process((sys.executable, __file__, 'limits'), Path.cwd(), {}, Limits())
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    raise SystemExit(result.returncode)
elif mode == 'probe-procfs':
    # Reproducible read-only capability evidence. This deliberately does not use
    # the runtime adapter: it measures whether the adapter's prerequisite exists.
    import tempfile
    def read_bounded(path):
        with path.open('rb', buffering=0) as handle:
            data = handle.read(65537)
        if len(data) > 65536:
            raise RuntimeError('metadata exceeds 64 KiB')
        return data
    with tempfile.TemporaryDirectory(prefix='historycrate-procfs-probe-') as tmp:
        root = Path(tmp)
        direct = subprocess.Popen((sys.executable, __file__, 'family', str(32 * 1024 * 1024),
                                   str(root / 'pid')), start_new_session=True)
        try:
            deadline = time.monotonic() + 2
            while not (root / 'pid').exists() and time.monotonic() < deadline:
                time.sleep(.01)
            child = int((root / 'pid').read_text())
            time.sleep(.15)
            result = {'controller': os.getpid(), 'direct': direct.pid, 'thread_child': child,
                      'probe': 'max4096 directory entries; max65536 metadata bytes/read; max1s scan',
                      'tasks': [], 'processes': []}
            with os.scandir(Path('/proc') / str(direct.pid) / 'task') as tasks:
                for index, task in enumerate(tasks):
                    if index >= 4096:
                        raise RuntimeError('too many task entries')
                    item = {'tid': int(task.name), 'exists': True}
                    try:
                        item['children'] = read_bounded(Path(task.path) / 'children').decode()
                    except OSError as exc:
                        item['children_errno'] = exc.errno
                    result['tasks'].append(item)
            start, entries = time.monotonic(), 0
            with os.scandir('/proc') as items:
                for item in items:
                    entries += 1
                    if entries > 4096 or time.monotonic() - start > 1:
                        raise RuntimeError('scan budget exceeded')
                    if not item.name.isdecimal():
                        continue
                    try:
                        status = read_bounded(Path(item.path) / 'status')
                        raw = read_bounded(Path(item.path) / 'stat')
                    except FileNotFoundError:
                        continue
                    fields = raw[raw.rindex(b')') + 2:].split()
                    selected = {}
                    for line in status.splitlines():
                        key, _, value = line.partition(b':')
                        if key in (b'Name', b'Pid', b'PPid', b'Tgid', b'VmRSS'):
                            selected[key.decode()] = value.strip().decode()
                    selected.update({'stat_ppid': int(fields[1]), 'pgrp': int(fields[2]),
                                     'session': int(fields[3]), 'starttime': int(fields[19]),
                                     'state': fields[0].decode()})
                    result['processes'].append(selected)
            result.update({'entries': entries, 'scan_seconds': time.monotonic() - start})
            print(json.dumps(result, indent=2))
        finally:
            os.killpg(direct.pid, signal.SIGTERM)
            direct.wait(timeout=2)
elif mode == 'exit':
    sys.exit(int(sys.argv[2]))
else:
    raise SystemExit('unknown fixture')
