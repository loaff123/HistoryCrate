"""Original MIT tiny Git stores, authored without executing source Git/config."""
import hashlib
from pathlib import Path
import struct
import zlib


def canonical(kind, data):
    raw = kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data
    return hashlib.sha1(raw).hexdigest(), raw


def store(path, *, bare=True):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True)
    for name in ('objects', 'objects/info', 'objects/pack', 'refs', 'refs/heads', 'info'):
        (path / name).mkdir(mode=0o700)
    (path / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = ' + str(bare).lower() + '\n')
    (path / 'HEAD').write_text('ref: refs/heads/main\n')
    return path


def loose(path, kind, data):
    oid, raw = canonical(kind, data)
    target = path / 'objects' / oid[:2] / oid[2:]
    target.parent.mkdir(mode=0o700, exist_ok=True)
    target.write_bytes(zlib.compress(raw))
    return oid


def tree_bytes(entries):
    return b''.join(f'{mode:o} '.encode() + name + b'\0' + bytes.fromhex(oid)
                    for mode, name, oid in entries)


def commit_bytes(tree, parents=(), message=b'Original MIT fixture\n'):
    return (f'tree {tree}\n'.encode() + b''.join(f'parent {p}\n'.encode() for p in parents)
            + b'author Fixture <fixture@example.invalid> 978307200 +0000\n'
            + b'committer Fixture <fixture@example.invalid> 978307200 +0000\n\n' + message)


def history(path, data=b'hello\n'):
    blob = loose(path, 'blob', data)
    tree = loose(path, 'tree', tree_bytes(((0o100644, b'file', blob),)))
    commit = loose(path, 'commit', commit_bytes(tree))
    (path / 'refs/heads/main').write_text(commit + '\n')
    return commit, tree, blob


def _pack_header(kind, size):
    value = (kind << 4) | (size & 15)
    size >>= 4
    result = bytearray()
    while size:
        result.append(value | 128)
        value = size & 127
        size >>= 7
    result.append(value)
    return bytes(result)


def pack(path, objects, *, missing_base=None):
    result = bytearray(b'PACK' + struct.pack('>II', 2, len(objects)))
    kinds = {'commit': 1, 'tree': 2, 'blob': 3, 'tag': 4}
    for kind, data in objects:
        if missing_base is not None:
            # Well-framed REF_DELTA whose base is deliberately absent.
            result += _pack_header(7, len(data)) + bytes.fromhex(missing_base) + zlib.compress(data)
        else:
            result += _pack_header(kinds[kind], len(data)) + zlib.compress(data)
    digest = hashlib.sha1(result).digest()
    result += digest
    target = path / 'objects/pack' / ('pack-' + digest.hex() + '.pack')
    target.write_bytes(result)
    return target


def hashes(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(path.rglob('*')) if p.is_file() and not p.is_symlink()}
