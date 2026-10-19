"""Explicit native test dependencies; missing tools fail, never skip or auto-fetch."""
import os
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
GIT = Path(os.environ.get('HISTORYCRATE_GIT', '/usr/local/bin/git'))
LFS = Path(os.environ.get('HISTORYCRATE_GIT_LFS', str(ROOT/'tools/git-lfs-3.8.0/git-lfs')))
# The profile's official make-install layout; native qualification verifies it.
GIT_EXEC = GIT.parent.parent/'libexec/git-core'
