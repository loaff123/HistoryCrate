"""Frozen trusted-local-v1 thresholds and directly accounted counters.

These are controller thresholds, sampled observations or per-process limits as
labelled. They do not constitute OS-wide disk, memory or CPU containment.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, replace
from types import MappingProxyType
from typing import Mapping

from .errors import CrateError

_MiB = 1024 ** 2
_GiB = 1024 ** 3


@dataclass(frozen=True, slots=True)
class Limits:
    repositories: int = 32
    root_groups: int = 32
    selected_root_commits: int = 64
    commits: int = 50_000
    git_objects: int = 250_000
    gitlink_occurrences: int = 100_000
    commit_path_visits: int = 5_000_000
    repository_depth: int = 16
    path_depth: int = 64
    bundle_seed_refs: int = 8_192
    git_object_bytes: int = 256 * _MiB
    lfs_payload_bytes: int = 512 * _MiB
    source_git_bytes: int = 2 * _GiB
    unique_lfs_bytes: int = 2 * _GiB
    scratch_bytes: int = 8 * _GiB
    packet_bytes: int = 4 * _GiB
    restore_bytes: int = 4 * _GiB
    combined_bytes: int = 12 * _GiB
    spec_bytes: int = 16 * _MiB
    manifest_bytes: int = 16 * _MiB
    config_bytes: int = _MiB
    gitmodules_bytes: int = _MiB
    gitattributes_bytes: int = 256 * 1024
    pointer_bytes: int = 1024
    path_bytes: int = 1024
    component_bytes: int = 255
    command_wall_seconds: int = 300
    command_cpu_seconds: int = 180
    command_file_bytes: int = 4 * _GiB
    job_wall_seconds: int = 1800
    observed_rss_bytes: int = _GiB
    native_commands: int = 1
    command_descriptors: int = 256
    captured_bytes: int = 16 * _MiB
    diagnostics: int = 1000
    observation_entries: int = 4096

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 0 or value > field.default:
                raise CrateError("INVALID_LIMIT", 2, {"resource": field.name, "reason": "expected nonnegative integer no greater than profile threshold"})

    def lower(self, overrides: dict[str, int]) -> Limits:
        if not isinstance(overrides, dict):
            raise CrateError("INVALID_LIMIT", 2, {"reason": "limits must be an object"})
        known = {field.name for field in fields(self)}
        for name, value in overrides.items():
            if name not in known:
                raise CrateError("INVALID_LIMIT", 2, {"reason": "unknown resource"})
            if type(value) is not int or value < 0 or value > getattr(self, name):
                raise CrateError("INVALID_LIMIT", 2, {"resource": name, "reason": "limit must be a nonnegative integer and cannot increase"})
        return replace(self, **overrides)

    def as_dict(self) -> dict[str, dict[str, object]]:
        """Report configuration and its actual enforcement category."""
        return {field.name: {"threshold": getattr(self, field.name), "kind": _KINDS.get(field.name, "controller-admission-count")}
                for field in fields(self)}


_KINDS = MappingProxyType({
    "commits": "controller-traversal-count",
    "git_objects": "controller-traversal-count",
    "gitlink_occurrences": "controller-traversal-count",
    "commit_path_visits": "controller-traversal-count",
    "repository_depth": "controller-traversal-count",
    "path_depth": "controller-traversal-count",
    "git_object_bytes": "declared-size-admission-and-streaming-verified-bytes",
    "lfs_payload_bytes": "declared-size-admission-and-streaming-verified-bytes",
    "source_git_bytes": "controller-inventory-copy-accounting",
    "unique_lfs_bytes": "controller-inventory-copy-accounting",
    "scratch_bytes": "preflight-and-observed-abort-threshold-native-overshoot-possible",
    "combined_bytes": "preflight-and-observed-abort-threshold-native-overshoot-possible",
    "packet_bytes": "exact-verified-inventory-and-bounded-controller-copy",
    "restore_bytes": "exact-verified-inventory-and-bounded-controller-copy",
    "spec_bytes": "controller-bounded-read",
    "manifest_bytes": "controller-bounded-read",
    "config_bytes": "controller-bounded-read",
    "gitmodules_bytes": "controller-bounded-read",
    "gitattributes_bytes": "controller-bounded-read",
    "pointer_bytes": "controller-parser-admission",
    "path_bytes": "controller-parser-admission",
    "component_bytes": "controller-parser-admission",
    "command_wall_seconds": "parent-command-timeout",
    "command_cpu_seconds": "per-process-RLIMIT_CPU",
    "command_file_bytes": "per-process-RLIMIT_FSIZE",
    "job_wall_seconds": "controller-watchdog",
    "observed_rss_bytes": "sampled-RSS-abort-threshold-not-memory-cap",
    "native_commands": "adapter-scheduling",
    "command_descriptors": "per-process-RLIMIT_NOFILE",
    "captured_bytes": "bounded-capture-per-stdout-or-stderr",
    "diagnostics": "controller-count-truncation-blocks",
    "observation_entries": "controller-observation-traversal-count",
})


class Budget:
    """Additive accounting for a single explicitly chosen counter scope.

    The caller selects the scope: job totals, one object, or one command.
    Do not charge successive RSS/scratch samples as accumulated byte totals.
    Non-additive observations must be compared to their thresholds separately.
    """

    def __init__(self, limits: Limits | None = None):
        self.limits = limits if limits is not None else Limits()
        if not isinstance(self.limits, Limits):
            raise CrateError("INTERNAL_INVARIANT", 6, {"reason": "invalid budget limits"})
        self._used: dict[str, int] = {}

    @property
    def used(self) -> Mapping[str, int]:
        return MappingProxyType(self._used)

    def charge(self, resource: str, amount: int) -> None:
        known = {field.name for field in fields(self.limits)}
        if not isinstance(resource, str) or resource not in known or type(amount) is not int or amount < 0:
            raise CrateError("INTERNAL_INVARIANT", 6, {"reason": "unknown resource or invalid charge"})
        used = self._used.get(resource, 0)
        threshold = getattr(self.limits, resource)
        if amount > threshold - used:
            raise CrateError("BUDGET_EXCEEDED", 5, {"resource": resource, "threshold": threshold, "used": used, "requested": amount})
        self._used[resource] = used + amount
