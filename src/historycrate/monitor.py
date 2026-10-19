"""Bounded controller-copy observations shared by source and payload stages.

Checks are approximate samples, not an OS memory limit or filesystem quota.
"""
from __future__ import annotations

import os
import time

from .errors import CrateError
from .paths import _ancestors, open_directory
from .process import _Observer

_RESERVE = 64 * 1024 * 1024


def _fail(code, **context):
    raise CrateError(code, 5, context)


class CopyMonitor:
    def __init__(self, job):
        self.job = job
        self.deadline = job.native.started + job.limits.job_wall_seconds
        self.observer = _Observer(job.limits, job.native.started, self.deadline, getattr(job, "observation_root", job.root))
        if not hasattr(job, 'controller_observations'):
            job.controller_observations = []
        self.report = self.observer.report()
        job.controller_observations.append(self.report)

    def check(self):
        if time.monotonic() > self.deadline:
            _fail('BUDGET_EXCEEDED', resource='job_wall_seconds')
        try:
            self.observer.sample()
            self.observer.sample_scratch()
            scratch = self.observer.scratch_samples[-1]['observed_bytes']
            combined = scratch + getattr(self.job, 'external_materialized_bytes', 0)
            if combined > self.job.limits.combined_bytes:
                _fail('BUDGET_EXCEEDED', resource='combined_bytes', observed=combined)
        finally:
            self.report.update(self.observer.report())

    def is_scratch(self, directory_fd):
        root = open_directory(getattr(self.job, "observation_root", self.job.root))
        try:
            info = os.fstat(root)
            return (info.st_dev, info.st_ino) in _ancestors(directory_fd)
        finally:
            os.close(root)

    def allocation(self, directory_fd, amount):
        self.check()
        scratch = self.observer.scratch_samples[-1]['observed_bytes']
        added_scratch = amount if self.is_scratch(directory_fd) else 0
        if scratch + added_scratch > self.job.limits.scratch_bytes:
            _fail('BUDGET_EXCEEDED', resource='scratch_bytes', requested=added_scratch,
                  observed=scratch, threshold=self.job.limits.scratch_bytes)
        if scratch + getattr(self.job, 'external_materialized_bytes', 0) + amount > self.job.limits.combined_bytes:
            _fail('BUDGET_EXCEEDED', resource='combined_bytes', requested=amount)
        space = os.fstatvfs(directory_fd)
        if space.f_bavail * space.f_frsize < amount + _RESERVE:
            _fail('INSUFFICIENT_SPACE', requested=amount, reserve=_RESERVE)
