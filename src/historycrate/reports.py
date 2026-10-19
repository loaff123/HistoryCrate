"""Bounded version-one reports, with sampled observations explicitly labelled."""
from __future__ import annotations

import hashlib
import itertools
import time

from .errors import CrateError

PACKET_CHECKS = ['artifact-hashes', 'native-fsck', 'exact-bundle-object-sets',
                 'recomputed-historical-closure', 'required-lfs-bytes']
INSPECT_CHECKS = ['owned-source-acquisition', 'native-fsck', 'selected-historical-closure',
                  'historical-attributes-and-clean-roundtrip', 'required-lfs-bytes', 'source-recheck']


def selection_warnings(spec, closure, limits=None):
    """Derive unused mappings from verified demand; bound before publication."""
    warnings = []
    maximum = min(spec.limits.diagnostics, limits.diagnostics) if limits is not None else spec.limits.diagnostics
    used = {(link.parent_repository, link.path, link.url_sha256, link.child_repository)
            for link in closure.gitlinks}

    def append(code, context):
        if len(warnings) >= maximum:
            raise CrateError('DIAGNOSTIC_LIMIT', 5,
                             {'diagnostics_truncated': True, 'threshold': maximum})
        warnings.append({'code': code, 'severity': 'warning', 'context': context})

    for repo in spec.repositories:
        if repo.id not in closure.seeds:
            append('UNUSED_REPOSITORY', {'repository': repo.id})
    for binding in spec.bindings:
        digest = hashlib.sha256(binding.url.encode('utf-8')).hexdigest()
        if (binding.parent_repository, binding.path, digest, binding.child_repository) not in used:
            append('UNUSED_BINDING', {'repository': binding.parent_repository, 'path': binding.path,
                                      'url_sha256': digest, 'child_repository': binding.child_repository})
    return warnings


def base_report(limits, trust=False, command=None):
    return {'report_version': 1, 'profile': 'trusted-local-v1', 'command': command,
            'status': 'blocked', 'publication': 'not-published', 'trust_acknowledged': trust,
            'counts': {}, 'limits': limits.as_dict(), 'observations': {
                'kind': 'sampled-observations-not-resource-peaks', 'native_commands_observed': 0,
                'native_command_count_kind': 'returned-adapter-records; failed-process-observations-may-appear-only-in-diagnostics',
                'max_sampled_process_rss_bytes': None, 'max_sampled_scratch_bytes': None,
                'max_sample_gap_seconds': None, 'descendant_discovery_methods': [], 'uncertain_cleanup_reports': 0,
                'rss_sample_count': 0, 'scratch_sample_count': 0},
            'preflight': {'kind': 'per-allocation-preflight-checks-not-reservations',
                          'estimates_recorded': False},
            'structural_checks': [], 'rehearsed': [], 'diagnostics': [], 'diagnostics_truncated': False,
            'os_sandbox': False, 'network_containment': False, 'hard_job_quota': False,
            'resource_limitations': ['RSS and scratch observations are sampled; native peaks may be larger.',
                                     'Per-process limits are not aggregate memory, task or filesystem quotas.']}


def observe(report, job, started):
    """Summarize existing samples only; never invent measurements or peaks."""
    report['elapsed_seconds'] = max(0.0, time.monotonic() - started)
    if job is None or job.native is None:
        return
    result = report['observations']
    records = job.native.records
    result['native_commands_observed'] = len(records)
    measurements = (record.get('observations', {}) for record in records)
    methods = set()
    for measurement in itertools.chain(measurements, getattr(job, 'controller_observations', ())):
        gap = measurement.get('max_sample_gap_seconds')
        if gap is not None:
            result['max_sample_gap_seconds'] = max(result['max_sample_gap_seconds'] or 0, gap)
        method = measurement.get('descendant_discovery_method')
        if method is not None:
            methods.add(method)
        if measurement.get('cleanup', {}).get('uncertain'):
            result['uncertain_cleanup_reports'] += 1
        result['rss_sample_count'] += len(measurement.get('samples', ()))
        result['scratch_sample_count'] += len(measurement.get('scratch_samples', ()))
        if measurement.get('scratch_samples'):
            result['max_sampled_scratch_bytes'] = max(result['max_sampled_scratch_bytes'] or 0,
                                                       measurement.get('max_scratch_bytes', 0))
        for process in measurement.get('processes', ()):
            result['max_sampled_process_rss_bytes'] = max(result['max_sampled_process_rss_bytes'] or 0,
                                                           process.get('max_rss_bytes', 0))
    result['descendant_discovery_methods'] = sorted(methods)
    report['controller_accounting'] = {'scope': 'main-phase-direct-counters', 'used': dict(job.budget.used)}


def remediation(exit_code, publication):
    if publication != 'not-published':
        return 'Preserve the final directory. Inspect and verify it before relying on it; do not overwrite it.'
    return {2: 'Check the command arguments and selection syntax.',
            3: 'Use supported owned local inputs and the explicitly qualified toolchain.',
            4: 'Repair or supply the identified local input, stop concurrent writers, and rerun.',
            5: 'Reduce the selection or resource use. Profile limits cannot be raised.',
            6: 'Check the output location and local I/O failure before rerunning.',
            130: 'Rerun only after the cancelled operation and its owned cleanup have finished.'}[exit_code]
