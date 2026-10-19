# HistoryCrate

HistoryCrate transfers selected local Git history, historical submodule dependencies, and the exact local Git LFS payloads they require. It restores an included root revision to a fresh directory without rewriting commit IDs or running repository code.

**Trusted local data only.** Source stores, caches and received packets must already be trusted, owned by you, stable, and not writable by other users. Native Git/LFS run with normal user privileges. There is no OS sandbox, network namespace, hard aggregate memory limit, or hard filesystem quota. Integrity checks do not establish who created a packet or make hostile native data safe.

Committed secrets, if any, are also preserved. Review the selected history before sharing; this tool does not redact it.

This is a source handoff utility, not a reproducible-build system. Uncommitted files, original branch/tag names, hooks/configuration, compilers, dependencies outside Git/LFS, and services are outside its scope.

## Requirements

- Linux x86-64 on a case-sensitive local filesystem
- Python 3.11 or newer
- Explicit absolute paths to Git 2.52.0 and Git LFS 3.8.0
- Both executables from a trusted installation, outside source, packet and output directories
- A private owned output parent; an existing destination is always refused

The initial compatibility profile accepts those exact native versions. HistoryCrate never installs dependencies. Its `doctor` command exercises the selected binaries using original tiny fixtures; ordinary commands recheck the selected toolchain and required capabilities. CLI bootstrap and private jobs use guarded `/tmp` placement, ignoring inherited `TMPDIR` or Python tempfile settings; a protected input containing that location is refused before bootstrap.

## Select local history

Create a UTF-8 JSON file. Commit IDs must be full, lowercase SHA-1 commit IDs. URLs identify exact historical bindings; they are never fetched or normalized.

```json
{
  "version": 1,
  "repositories": [
    {"id": "project", "git_dir": "/absolute/project/.git"},
    {"id": "data", "git_dir": "/absolute/data.git",
     "lfs_objects_dir": "/absolute/data.git/lfs/objects"}
  ],
  "roots": [
    {"id": "release", "repository": "project",
     "commits": ["0123456789abcdef0123456789abcdef01234567"]}
  ],
  "bindings": [
    {"parent_repository": "project", "path": "data",
     "url": "../data.git", "child_repository": "data"}
  ]
}
```

Replace the illustrative commit with a real selected commit. Omit unused repository/binding entries for a project without submodules. The default LFS cache is exactly `<git_dir>/lfs/objects`; an absent cache is allowed when no selected history needs an LFS payload. An ordinary `.git` directory, bare directory, or explicitly named absorbed submodule directory is accepted. Gitfile discovery and linked worktrees are unsupported.

HistoryCrate follows every selected commit's complete parent ancestry and every gitlink in every included historical tree, recursively. Renamed paths or changed literal URLs need separate bindings. A dependency object ID alone does not authorize choosing another local repository. Missing history or payloads block the entire operation; prepare or repair your local inputs outside HistoryCrate and rerun.

## Commands

Every data command requires the explicit trust acknowledgement and trusted tool paths:

```sh
historycrate doctor --git "$GIT" --git-lfs "$GIT_LFS"
historycrate inspect --spec selection.json --trust-local-data --git "$GIT" --git-lfs "$GIT_LFS"
historycrate pack --spec selection.json --out /private/output/packet --trust-local-data --git "$GIT" --git-lfs "$GIT_LFS"
historycrate verify --packet /private/output/packet --trust-local-data --git "$GIT" --git-lfs "$GIT_LFS"
historycrate verify --packet /private/output/packet --rehearse release FULL_COMMIT_ID --trust-local-data --git "$GIT" --git-lfs "$GIT_LFS"
historycrate restore --packet /private/output/packet --root release --commit FULL_COMMIT_ID --out /private/output/checkout --trust-local-data --git "$GIT" --git-lfs "$GIT_LFS"
historycrate explain --packet /private/output/packet --repo project --commit FULL_COMMIT_ID --trust-local-data --git "$GIT" --git-lfs "$GIT_LFS"
```

`inspect` produces no final packet. `pack` repeats all current-source validation. `verify` independently imports bundles into fresh repositories and recomputes historical closure; it does not trust manifest claims. Without `--rehearse`, verification does not check out every included revision. Reports enumerate only actual rehearsals. `restore` accepts a selected root or one of its included ancestors, preserves original IDs, and verifies native clean status before publication.

`explain` returns immediate selection, parent or gitlink inclusion reasons and matching LFS occurrences. Repeated queries can walk these edges back to a selected root.

JSON stdout is versioned with `report_version: 1`. Errors use stable codes and omit raw URL credentials/configuration. Exit categories: 0 success; 2 invalid invocation/schema; 3 unsupported profile/toolchain; 4 missing, corrupt, ambiguous or changing data; 5 budget exhaustion; 6 publication/internal failure; 130 cancellation. A successful rename is the publication commit point. A subsequent durability/reporting error returns `published-durability-uncertain`, preserves the validated output and requires operator inspection rather than deletion/retry over it.

## Restored Git behavior

Restored repositories have detached HEADs, only owned HistoryCrate seed refs, embedded `.git` directories for submodules, and inert local offline submodule registrations. Original `.gitmodules` files remain unchanged. Native recursive submodule status, cached/worktree diffs, porcelain status, index flags, every tracked file's native clean/hash, and hydrated file/cache payload hashes are checked.

The local LFS driver uses the qualified absolute executable path and `filter-process --skip`, plus fixed clean and skip-smudge commands. It remains valid after the output rename and from nested working directories. Keep that trusted installation available for normal Git use. A later manual Git checkout leaves LFS pointers and does not recursively hydrate another revision. Run HistoryCrate restore into another fresh destination for that operation.

No automatic fetch, clone, submodule update, custom filter, repository hook, build, or repository script is run. Future commands you run yourself are outside HistoryCrate's control.

## Boundaries and alternatives

The profile refuses symlinks, unsafe or case-colliding paths, `.lfsconfig`, unsupported attributes/filters/encodings, shallow/partial/alternate/replacement stores, SHA-256 repositories, reftable, and custom LFS transfers. Supported text/eol checkout conversions must clean back to the original blob ID. Empty LFS-tracked files remain ordinary empty files. Literal pointer-looking files without effective LFS attributes remain ordinary Git bytes.

Limits include 32 repositories, 50,000 commits, 250,000 selected objects, a 1,800-second job deadline, and an unchanged 4,096-entry observation traversal bound. The smaller observation bound can reject a store or scratch layout below other maxima. Users may lower limits with repeatable `--limit NAME=INTEGER` arguments (or the spec limits object); no success or capacity claim follows merely from a published maximum. RSS and scratch totals are sampled with possible overshoot. CPU/file-size/descriptor RLIMITs apply per process, not to all descendants as an aggregate.

Copying complete bare stores plus the same required LFS cache is a simpler manual alternative. Selected-history bundles may reduce transfer size when unrelated history exists. No fixed compression ratio or usability improvement is promised. In the pinned Cholla experiment, the actual packet was 24,129,771 compressed bytes versus 86,034,930 for both full stores, using the same required LFS cache (71.95% smaller; zero LFS-cache savings). Three historical revisions passed independent native restore checks. See `docs/qualification.md` for the API/CLI scope, preserved harness failure/continuation, and limitations.

## Development and external fixture

Regular tests use original MIT fixtures. The Cholla test is opt-in, requires separately prepared local inputs, and never runs project code. Full third-party histories and payloads are not distributed in this source package. See `docs/cholla-reproduction.md` and `tests/external/cholla.json` for pins, notices, expectations and fair baseline instructions.

The final qualification report distinguishes completed checks from pending gates. Public publication and exact-release-commit CI are separate actions and are not implied by a local candidate archive.

The supplied read-only Linux CI workflow retains the full source suite and adds a separate installed-wheel gate. It installs a built wheel into a fresh virtual environment, copies only the tests/configuration outside the checkout, unsets `PYTHONPATH` and `PYTHONHOME`, verifies package origins remain in that environment, runs selected native/CLI tests with no skips, and checks the installed command entrypoint and doctor. The complete source suite remains responsible for source-layout-specific tests. This workflow has not yet run remotely on a release commit.

Run mandatory original-fixture tests with explicit tool paths:

```sh
export HISTORYCRATE_GIT="$GIT" HISTORYCRATE_GIT_LFS="$GIT_LFS"
PYTHONPATH=src python -m unittest discover -s tests -t . -v
PYTHONPATH=src python -m unittest tests.oracle.restore -v
```

Missing native dependencies fail the tests; they are never silently skipped or downloaded. The clean distribution excludes native binaries. Install this package using `python -m pip install /path/to/historycrate-0.1.0a1-py3-none-any.whl`, then select the already trusted native tools explicitly.
