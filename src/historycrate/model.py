"""Immutable selection records, validated at the schema boundary."""
from dataclasses import dataclass
from pathlib import Path

from .limits import Limits


@dataclass(frozen=True, slots=True)
class RepoSpec:
    id: str
    git_dir: Path
    lfs_objects_dir: Path


@dataclass(frozen=True, slots=True)
class RootSpec:
    id: str
    repository: str
    commits: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Binding:
    parent_repository: str
    path: str
    url: str
    child_repository: str


@dataclass(frozen=True, slots=True)
class Spec:
    version: int
    repositories: tuple[RepoSpec, ...]
    roots: tuple[RootSpec, ...]
    bindings: tuple[Binding, ...]
    limits: Limits


@dataclass(frozen=True, slots=True)
class ObjectRecord:
    repository: str
    oid: str
    kind: str
    size: int


@dataclass(frozen=True, slots=True)
class CommitRecord:
    repository: str
    oid: str
    tree: str
    parents: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TreeEntry:
    mode: int
    name: bytes
    oid: str


@dataclass(frozen=True, slots=True)
class GitlinkRecord:
    parent_repository: str
    parent_commit: str
    path: str
    name: str
    url_sha256: str
    child_repository: str
    child_commit: str


@dataclass(frozen=True, slots=True)
class LfsOccurrence:
    repository: str
    commit: str
    path: str
    blob_oid: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class PayloadRecord:
    sha256: str
    size: int
    private_path: Path


@dataclass(frozen=True, slots=True)
class PayloadSet:
    records: tuple[PayloadRecord, ...]


@dataclass(frozen=True, slots=True)
class AcquiredRepo:
    id: str
    stage_git_dir: Path
    source_inventory_digest: str


@dataclass(frozen=True, slots=True)
class Closure:
    roots: tuple[RootSpec, ...]
    root_ancestors: object
    seeds: object
    commits: tuple[CommitRecord, ...]
    objects: tuple[ObjectRecord, ...]
    gitlinks: tuple[GitlinkRecord, ...]
    lfs: tuple[LfsOccurrence, ...]

    def __post_init__(self):
        from types import MappingProxyType
        object.__setattr__(self, 'root_ancestors', MappingProxyType({k:tuple(v) for k,v in self.root_ancestors.items()}))
        object.__setattr__(self, 'seeds', MappingProxyType({k:tuple(v) for k,v in self.seeds.items()}))


@dataclass(frozen=True, slots=True)
class VerifiedPacket:
    private_root: Path
    closure: Closure
    payloads: PayloadSet
    artifact_digest: str


@dataclass(frozen=True, slots=True)
class RestoreResult:
    root_id: str
    commit: str
    destination: Path | None
    checks: tuple[str, ...]
