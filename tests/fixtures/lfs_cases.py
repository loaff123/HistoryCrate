"""Original tiny LFS fixtures. No downloaded history or data is used."""
import hashlib
from pathlib import Path

LFS_ATTRIBUTES = {'filter': 'lfs', 'text': 'unset', 'eol': 'unspecified',
                  'ident': 'unspecified', 'working-tree-encoding': 'unspecified'}
ORDINARY_ATTRIBUTES = dict(LFS_ATTRIBUTES, filter='unspecified')
PAYLOAD = b'Original HistoryCrate LFS fixture\0\r\nbytes\xff\n'


def pointer(payload=PAYLOAD, *, sha256=None, size=None):
    digest = hashlib.sha256(payload).hexdigest() if sha256 is None else sha256
    count = len(payload) if size is None else size
    return f'version https://git-lfs.github.com/spec/v1\noid sha256:{digest}\nsize {count}\n'.encode()


def cache_file(cache: Path, payload=PAYLOAD, *, sha256=None):
    digest = hashlib.sha256(payload).hexdigest() if sha256 is None else sha256
    return cache / digest[:2] / digest[2:4] / digest


def write_cache(cache: Path, payload=PAYLOAD, *, sha256=None):
    path = cache_file(cache, payload, sha256=sha256)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o600)
    return path
