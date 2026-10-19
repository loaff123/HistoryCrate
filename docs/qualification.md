# Qualification and public source status

The `0.1.0a1` source candidate was tested locally on 2026-10-19 using Linux x86-64, Python 3.12.14, Git 2.52.0 and Git LFS 3.8.0. Its profile is **trusted-local-v1**, with ordinary native-process privileges, no OS sandbox and no hard aggregate quota. The hosted Linux qualification below is a separate result; other platforms and native versions were not qualified.

## Original-fixture and independent review gates

- Final production/CLI gate: **438 tests passed, zero failures/errors/skips, 167.583 seconds**. Discovery plus the separate native restore oracle ran; all 61 reviewed source/test/fixture-metadata hashes stayed unchanged.
- Independent reviews covered strict packets and selected refs, fresh semantic verification, exact LFS bytes, recursive native-clean restoration, prepublication refusals, no-replace races, and postcommit return/cleanup/reporting interruptions. Bootstrap temporary placement, input-contained executables and unused declared sources received explicit refusal regressions.
- A later harness-only correction passed **16 focused tests, zero skips, 12.846 seconds**, including independent adversarial cases. All 22 production files stayed unchanged. The prepublication distribution receipt recorded its complete test count, installed-wheel smoke and archive hashes. That receipt belongs to the local handoff and is not included in this public repository. Those checks do not require another expensive Cholla run.
- Doctor exercised 24 capability checks with 40 recorded adapter commands. Its lowered observer tests are original controlled fixtures, not resource containment proofs.

Ordinary tests use original MIT fixtures and never download external inputs. Version/Trace2-conflict negative cases deliberately alter probe responses or trace data after actual native calls; they do not claim a second old tool installation. Unmodified internal-Git Trace2 and executable-identity checks also ran.

## Real Cholla results

The pinned inputs, rights notice and reproduction instructions are in `cholla-reproduction.md` and `tests/external/cholla.json`. No Cholla code, build, hook or project script was executed. No native Git command ran in the frozen originals.

Exact independent native sets agreed with the actual packet:

| Quantity | Observed |
|---|---:|
| Root commits / dependency commits | 2,518 / 12 |
| Historical child seeds | 6 |
| Selected Git objects | 15,402 |
| Historical gitlinks / LFS occurrences | 348 / 34 |
| Distinct required LFS payloads | 11 |
| Required payload bytes | 28,989,160 |
| Charged historical path visits per closure | 658,937 |

Production `create_packet` built and freshly verified the packet before publication: **1,264.859 seconds and 63,758 recorded native commands**. A separate recipient Job, given only a copied packet, freshly verified it and restored three exact revisions: **959.646 seconds and 35,340 recorded native commands**. Each Job remained below the unchanged 1,800-second deadline. The 4,096-entry observation bound and all other profile thresholds were unchanged.

| Restored root | Child state | Restore API seconds |
|---|---|---:|
| `988e4c5bb8e343d3e3bc4f10cf354595e4b660e9` | `e8fc667aec7f7f367fdfd1329b81105e1b5f083a`; one hydrated file | 42.359 |
| `96e92f3413a5afeea240593d99e6869d597a78f9` | No child path/repository | 47.054 |
| `d18e7bb8e167cea183e7da56f2043b85cab50068` | `66d5928213b495c2fef61b0653b90a25ae3aa7cf`; five hydrated files | 64.452 |

The independent restored-output oracle passed all three cases in 81.744 seconds: exact IDs, native fsck, persistent inert configuration, recursive submodule status, index flags, every tracked file's checkout bytes/mode/clean hash, exact LFS worktree/cache bytes, and clean diffs/status. This covered 1,065 tracked-file occurrences across the three outputs. It does not mean every included ancestor was rehearsed.

### Recorded harness failure and bounded continuation

The initial run passed every expensive API/native-output phase, then failed its *in-process* negative CLI test. The original inline exit/diagnostic was not retained. A miniature 96-MiB retained-memory reproduction confirmed exit 6 from doctor's deliberately lowered 64-MiB descendant self-test, a mechanism consistent with the original harness's large retained controller memory. A fresh real CLI process on the identical damaged packet correctly returned exit 4.

Only the external harness changed: negative calls now launch fresh `python -m historycrate` processes and persist stdout/stderr/exit status before assertions. Independent review approved a narrowly hash-bound continuation. It revalidated the original receipt, production/tool identities, both intact packet copies and all 55 original files, then ran only the negative cases and compression. The original failed receipt remains preserved; packet creation, verification and restores were not repeated or relabelled as a wholly successful first run.

Both actual CLI `verify` and `restore` negatives returned **exit 4, `INVALID_PACKET_LAYOUT`, not-published**, with no final output and unchanged intact packets. All 55 original source regular-file hashes still match the archived before snapshot. The continuation passed. Positive real-history workflow coverage is API-scoped; positive CLI end-to-end routing is covered by original fixtures, not a repeated full Cholla CLI workflow.

## Actual fair transfer comparison

The same streaming Python 3.12.14 tar/PAX and gzip-9 implementation (zlib 1.3.2), sorted regular files and normalized owner/time metadata was used for both alternatives. Both include exactly the same 11 required payloads; no extra cache or working-tree bloat was added.

| Artifact | Regular-file bytes | Compressed bytes |
|---|---:|---:|
| Both complete frozen stores | 111,849,478 | 86,034,930 |
| Actual HistoryCrate selected packet | 51,204,224 | 24,129,771 |

The selected packet was **71.95% smaller compressed in this experiment**. LFS-cache savings were **zero**. This is an actual product-packet measurement, distinct from the older native-bundle reference (86,030,778 versus 23,427,766 compressed bytes under LFS 3.6.1). A patched-runtime rerun of the older native-bundle workflow was not performed. Full-store copying is simpler manually; human usability, general speedup, all-ref LFS availability and fixed compression ratios are not established.

## Performance and observation scope

The original uncached inspection was deliberately interrupted after its last observed 327 commits, 19,400 commands and 223 seconds; it was not a pass. Reviewed bounded parsed-object caching then completed inspection in 411.146 seconds and 31,805 commands with identical pinned totals and unchanged sources. That is not a completed before/after speedup comparison. A separate original 12-commit repeated-tree fixture reduced native commands from 119 to 39 while preserving 16 unique objects and 36 path visits.

For the two completed API Jobs, process and phase-boundary samples reached 731,848,704 bytes for the controller, 193,695,744 bytes for a direct native process, and 287,270,159 bytes for scratch. The largest recorded observation gap was 24.289 seconds; zero uncertain-cleanup reports were recorded. These are maxima of samples, **not exact process/job peaks or hard aggregate limits**. The approved bounded procfs PPid/session fallback was used. Command counts mean returned adapter records, not all OS processes, and exclude separate oracle/probe/CLI work. Timing includes this harness/environment's overhead; it is not a controlled cross-platform benchmark.

All advertised maxima are refusal thresholds, not proven capacities. Source atime/global filesystem snapshots and escaped-descendant containment are not promised. Full third-party histories, LFS assets, native binaries and private raw logs are excluded from the distribution.

## Public source and hosted qualification

The reviewed 71-file source was published at [loaff123/HistoryCrate](https://github.com/loaff123/HistoryCrate) in commit `2e518c86d9c5b9be959e7b633672c4753c9929a5`. All published file object hashes and sizes matched the reviewed source snapshot. Its clean history contains only this project's reviewed original source, tests, fixture metadata, documentation and license notices. No third-party complete repository, LFS payload, native binary, private evidence log or package-registry release was uploaded.

The [first hosted run](https://github.com/loaff123/HistoryCrate/actions/runs/39242514671) failed during native-tool preparation because the Ubuntu runner lacked libcurl development headers. Both official downloads passed their pinned checksums; product tests had not run. Commit `5b5282674f85a43e47b397c12b22c500e712ca29` changed only the workflow and its source-manifest entry. It uses Git's documented `NO_CURL` build option for the offline CI toolchain. No production source or test was changed or skipped, and no host package installation was added.

[Hosted run 39242795973](https://github.com/loaff123/HistoryCrate/actions/runs/39242795973) completed successfully on that exact commit on 2026-10-19:

- Ubuntu 24.04 x86-64, Python 3.12, exact Git 2.52.0 and Git LFS 3.8.0.
- 445 mandatory source tests passed in 194.912 seconds, with zero failures, errors or skips.
- The source doctor passed 24 capability checks.
- The wheel built and installed successfully into a fresh virtual environment.
- Outside the checkout, 111 selected native/CLI tests passed in 27.041 seconds, with zero failures, errors or skips. `PYTHONPATH` and `PYTHONHOME` were unset, user-site imports were disabled, and all imported HistoryCrate modules resolved to the installed environment.
- The installed command entrypoint and installed doctor also passed; doctor again completed 24 capability checks.

The source-layout-specific tests remain in the complete source suite. The hosted workflow does not acquire Cholla inputs, execute third-party project code or repeat the real-history API workflow documented above. Its result is not a claim of OS sandboxing, hard aggregate resource limits, hostile-input safety, support for other native versions, or a full real-Cholla CLI run.

This remains a source-only alpha, with no tagged or package-registry release. `SOURCE-MANIFEST.json` records the current distributed files except itself; hashes establish byte identity, not upstream authenticity. The publication-status documentation update does not alter production source or tests. Refer to the [Actions history](https://github.com/loaff123/HistoryCrate/actions) for results tied to each later exact commit.
