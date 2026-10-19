# Trusted-local-v1 security boundary

Use only trusted, stable, user-owned local Git stores, LFS caches and received packets. Linux x86-64, a case-sensitive local filesystem, Python 3.11+, Git 2.52.0 and Git LFS 3.8.0 are the initial compatibility profile. Explicit absolute executable paths and `--trust-local-data` are required for data operations. Ownership checks and content hashes are not authentication and do not make hostile native data safe. Included committed bytes are preserved, including any secrets already committed in history or `.gitmodules`; HistoryCrate is not a secret scanner or redaction tool. Review what you are authorized to transfer before sharing a packet.

Git and Git LFS run with ordinary user privileges. There is no OS sandbox, network namespace, hard aggregate memory cap or filesystem quota. Malicious native data or a compromised trusted binary can retain user access. The tool does not change mounts, cgroups, authentication, system packages or host security settings. Treat patches to the supported native tools as a reason to requalify the toolchain, not as permission to accept untrusted packets.

## Controlled native boundary

All product native invocations use explicit executable identities, allowlisted environments, owned configuration, fixed argument construction and private staging. Original configurations, hooks, remotes and custom filters are never activated. Source refs are never installed. Git is never invoked in original source repositories. No clone, fetch, submodule update, build or repository script is run. Git transport denial and helper-trap tests demonstrate configuration hygiene; they are not kernel network containment.

The only executable filter is the fixed trusted LFS driver, with absolute executable and Git resolver paths. Persistent restore configuration uses `filter-process --skip`, fixed clean and skip-smudge commands, disabled hooks and offline submodule registrations. Original `.gitmodules` remains committed data. A later ordinary Git checkout leaves pointers; use a fresh HistoryCrate restore for another hydrated revision. Commands the operator subsequently runs are outside this boundary.

## Admission and integrity

Shallow/partial/alternate/replacement stores, linked worktrees, gitfile discovery, unsupported extensions/object formats, reftable and custom LFS transfers are refused. Whole copied stores receive native integrity/connectivity checks, including unreachable history. Historical paths, modes, metadata and exact effective attributes are checked before materialization. Symlinks, unsupported filters/encodings, historical `.lfsconfig`, unsafe/colliding paths and noncanonical LFS pointers are refused. Required payloads are streamed, size/hash-checked and independently clean-qualified. There is no automatic repair or unsafe fallback.

Packets require exact directory layout and canonical manifest/completion records. Fresh verification recomputes closure and native object inventories rather than trusting declarations. Original source/packet inventories are rechecked before output. Caches contain bounded immutable parsed values within one staging phase and are not reused across construction and verification. This is a trusted immutable-staging contract, not an adversarial filesystem snapshot guarantee. Read access may update access times.

## Resources and publication

RSS and scratch observations are samples and may miss peaks, short-lived/reparented processes or growth between samples. The unchanged 4,096-entry observation traversal bound can refuse layouts below other advertised maxima. Procfs discovery uses all-thread children files when supported; a bounded PPid/session fallback is allowed only for verified absence, never permission denial. Unreadable selected live processes block. Expected direct children are reaped; a malicious descendant escaping its session is outside the profile. Uncertain cleanup retains private scratch.

Inherited RLIMIT_AS is unchanged. CPU, file-size and descriptor RLIMITs are lowered only in children and apply per process. The controller enforces deadlines, admission counters, bounded capture/copies and preflight/observed storage thresholds. These are not hard aggregate OS quotas.

Outputs are new directories only. Atomic no-replace rename follows complete validation and input rechecks. Before commit, rollback removes only owned staging. After commit, durability/reporting failures preserve the output and return `published-durability-uncertain`. Inspect it before retrying at a fresh destination.

See `docs/qualification.md` for actual tested coverage and remaining gates. A local candidate is not evidence of public publication or exact-release-commit CI.

The CLI selects guarded `/tmp` placement for bootstrap and private jobs, ignores inherited `TMPDIR`/Python tempfile selection, and restores the caller's Python tempfile policy on return. Inputs containing the bootstrap location are refused before native qualification. Declared unused Git stores, caches and path-derived worktrees remain protected from output placement without acquiring their contents.
