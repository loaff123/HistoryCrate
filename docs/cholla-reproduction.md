# Cholla historical-handoff qualification

This is the pinned external-fixture recipe. The candidate completed real production API packet creation, fresh recipient verification, three restorations and independent native checks with Git 2.52.0 and Git LFS 3.8.0. Actual negative CLI cases and compression passed in a reviewed continuation after an in-process harness self-test failure; see `qualification.md` for that preserved distinction. The full positive CLI recipe below was not separately repeated on Cholla. The older native-bundle reference used LFS 3.6.1. Do not turn a timeout, unsupported fixture, missing public object, or failed download into a smaller successful case.

The machine-readable record is [`tests/external/cholla.json`](../tests/external/cholla.json).
It includes exact public source refs, selected commits, dependency seeds, all
required payload SHA-256s and sizes, three independent restoration expectations,
the original license text, and hashes of the research evidence. It is fixture
metadata, **not an input specification for the CLI**. No source histories or
payload assets belong in the HistoryCrate release.

## Sources, permissions, and trust boundary

- Root: <https://github.com/cholla-hydro/cholla>, recorded HEAD
  `191e59b063b4a4075738b0f016fd2203ab8b1523`.
- Dependency: <https://github.com/cholla-hydro/cholla-tests-data>, recorded HEAD
  `aceebfdd33b3a86b39ec354bfbd630284201b66b`.
- Selected root: `d18e7bb8e167cea183e7da56f2043b85cab50068`.
- Historical path: `cholla-tests-data`.
- Exact literal binding URL:
  `https://github.com/cholla-hydro/cholla-tests-data.git`.

Both observed `LICENSE.txt` files are the same 1,080-byte MIT notice, copyright
2018 Evan E. Schneider. Its Git blob is
`6fea013ea94bc1a219327b2855a753da1155804b`; its SHA-256 is
`0d24d0d26d43227625c30aeedbf67b0df53a3bb00ed3893aec219b40a6f5c90a`.
The exact UTF-8 notice is in the JSON's `license.original_notice_utf8`, including
the upstream final line `SOFTWARE.MAGE. ` and its trailing space/newline. Preserve
that text with any copied fixture portion. A notice in these files does not prove
license coverage for every third-party component throughout the entire histories.
The recipe distributes identifiers and expectations, not those histories.

Treat repositories and cache files as trusted local data owned by the operator
and stable while read. Never run Cholla code, hooks, tests, builds, data generators,
or repository-provided scripts. Never run Git in the frozen original source
repositories during qualification. Native operations use freshly initialized
owned staging repositories with copied object bytes, fixed clean configuration,
and no activated source configuration. No host, mount, network, or security
settings need changing. Offline command policy is not an OS network sandbox.

## Prefer the already acquired fixture

The existing research stores and required cache were independently rechecked on
2026-10-19 using filesystem reads and standard-library hashing only:

- All 55 source regular-file SHA-256s still match the recorded source snapshot.
- All 11 required payloads match both declared SHA-256 and size.
- Full stores contain 36,714 root Git objects and 205 dependency objects, based
  on the pack-index fanout counts. This header inspection is not a new native
  object-integrity proof.
- Root store: 22 regular files, 82,777,843 bytes, 30 total entries excluding root.
- Dependency store: 33 regular files, 29,071,635 bytes, 67 entries excluding root.
- The selected reference bundles' pack headers contain 15,351 root objects and
  51 dependency objects; their SHA-256s still match the recorded reference bytes.

The 29 MiB required cache is the dependency store's `lfs/objects` directory. Its
layout is `<oid[0:2]>/<oid[2:4]>/<oid>`, using the 64-character payload SHA-256.
The exact existing local paths are environment-specific coordination information,
not portable release metadata. No reacquisition is necessary while these verified
stores remain available.

## Optional networked fixture setup

Only use this setup when the local fixture is absent. It is separate from
HistoryCrate's offline operation and was **not rerun for this record**. Use a new
private directory, explicit qualified executable paths, an empty template,
isolated HOME/XDG directories, no system/global Git configuration, disabled
credentials and prompts, disabled hooks, skipped LFS smudging, and no recursive
submodule fetches. Do not install or run repository software.

1. Initialize two empty SHA-1 bare setup repositories. For every entry in
   `sources[].recorded_refs`, fetch that **exact OID** from that source's fixed
   HTTPS URL into its recorded ref name, with `--no-tags` and
   `--recurse-submodules=no`. The command shape is:

   ```sh
   "$GIT" -C "$SETUP_REPO" -c core.hooksPath=/dev/null \
     -c credential.helper= -c credential.interactive=false \
     fetch --no-tags --recurse-submodules=no "$FIXED_SOURCE_URL" \
     "$PINNED_OID:$PINNED_REF"
   ```

   Explicitly permit HTTPS only during this setup. Restore symbolic HEAD to
   `refs/heads/main`. Check annotated-tag peeling against `peeled_commit` when
   supplied. A moving branch name alone is not a pin. If the hosting service no
   longer serves a pinned OID, report fixture acquisition blocked; do not silently
   use current HEAD or a reduced history.

2. Before freezing the setup repositories, check native integrity and exact
   ancestor sets on these newly created setup repositories. Verify the six
   dependency seeds and the full dependency commit list in the JSON. Derive
   pointers from their committed blobs and compare the exact 11 OID/size pairs.

3. In the dependency setup repository, configure only the known public data URL
   as `origin`. Fetch LFS for the six explicit dependency seeds, not every current
   ref and not the root project's HEAD:

   ```sh
   "$GIT_LFS" fetch --all origin \
     34577601fd4abbdead625b1ea5cfb802a6325f9c \
     5a34430345d7dc746637364e8613642ebbbbc5c4 \
     66d5928213b495c2fef61b0653b90a25ae3aa7cf \
     e8fc667aec7f7f367fdfd1329b81105e1b5f083a \
     f134f963b7482f164acd4e97bd04bbd4603da35f \
     f47450dd2c229a277d4a081ff2993b6687b1912c
   ```

   Run from that setup repository with PATH and GIT_EXEC_PATH pinned to the
   qualified Git installation. Explicit refs with `--all` cover those refs'
   reachable history; see the [Git LFS 3.8.0 fetch manual](https://github.com/git-lfs/git-lfs/blob/v3.8.0/docs/man/git-lfs-fetch.adoc).
   Check the selected committed metadata before this networked setup step; do not
   activate unexpected `.lfsconfig`, custom transfer agents, or extensions. Verify
   payload bytes independently afterward. A partial fetch is not success.

4. Inventory every resulting regular file and SHA-256, then freeze these stores
   as the qualification inputs. Stop invoking native commands in them. Create
   all later native stages using raw copied object bytes and a fresh clean config.

The original full data refs referenced 86 payloads totaling 962,952,896 bytes, but
only the selected 11 payloads were downloaded. Fetching the other 75 would change
the baseline. Full-ref reconstruction also cannot promise byte-identical pack or
gzip output: packing, tool versions, and archive metadata can differ. If fetched
object inventories differ, explain that difference before comparing transfer size.

## Generate a private runtime specification

Supply absolute paths to the existing trusted stores and cache. Do not insert
machine-specific paths into the release JSON. For example, after setting
`CHOLLA_GIT_DIR`, `CHOLLA_DATA_GIT_DIR`, `CHOLLA_LFS_OBJECTS_DIR`, and `SPEC_OUT`:

```python
import json, os
from pathlib import Path

metadata = json.loads(Path("tests/external/cholla.json").read_text())
selection = metadata["selection"]
spec = {
    "version": 1,
    "repositories": [
        {"id": "cholla", "git_dir": os.environ["CHOLLA_GIT_DIR"]},
        {"id": "cholla-data", "git_dir": os.environ["CHOLLA_DATA_GIT_DIR"],
         "lfs_objects_dir": os.environ["CHOLLA_LFS_OBJECTS_DIR"]},
    ],
    "roots": [{"id": selection["root_id"], "repository": "cholla",
               "commits": selection["selected_root_commits"]}],
    "bindings": [selection["binding"]],
}
with open(os.environ["SPEC_OUT"], "x", encoding="utf-8") as output:
    json.dump(spec, output, indent=2)
    output.write("\n")
```

The spec intentionally does not raise limits or select an abbreviated history.
Output and scratch parents must be private, owned, case-sensitive, disjoint from
sources, and support atomic no-replace publication. Record the binary identities,
source snapshot, exact HistoryCrate revision, options, and elapsed time.

## Full-tool workflow and independent checks

The following is a full CLI reproduction recipe, not evidence that every positive CLI command was rerun on this real fixture. The recorded candidate used the API acceptance harness described below, plus original-fixture CLI gates. Run this recipe only with qualified commands and tools. Every native-using command
needs explicit `--git "$GIT" --git-lfs "$GIT_LFS"`; every data command additionally
needs `--trust-local-data`.

1. Run `doctor` with Git 2.52.0 and Git LFS 3.8.0. A previous green doctor report
   does not replace per-command identity checks.
2. Run `inspect --spec "$SPEC_OUT"` and compare exact root/dependency commit and
   object sets, gitlink occurrences, LFS occurrences, OIDs, and sizes with an
   independent oracle. Counts alone are insufficient. Expect 2,518 root commits,
   six historical child seeds, 12 child commits, and 11 unique payloads totaling
   28,989,160 bytes. The root has no LFS payloads, the child has no nested gitlinks.
3. Run `pack --spec "$SPEC_OUT" --out "$NEW_PACKET"`. Independently inventory
   packet regular-file bytes and hashes. No copied source configuration, hooks,
   arbitrary history, or missing required objects may appear.
4. Copy the packet to a disjoint private recipient location. Delete only owned
   disposable scratch; do not rename, remove, chmod, or hide the original sources.
   Verification/restoration must receive only the recipient packet and must not
   rely on original source paths. Check packet metadata for such path leakage.
5. Run `verify --packet "$RECIPIENT_PACKET"`, then `verify --rehearse` and `restore`
   for each of these exact root commits into three fresh destinations:

   - `988e4c5bb8e343d3e3bc4f10cf354595e4b660e9`: child
     `e8fc667aec7f7f367fdfd1329b81105e1b5f083a`, one hydrated file.
   - `96e92f3413a5afeea240593d99e6869d597a78f9`: no child path or child repository.
   - `d18e7bb8e167cea183e7da56f2043b85cab50068`: child
     `66d5928213b495c2fef61b0653b90a25ae3aa7cf`, five hydrated files.

   Example: `restore --packet "$RECIPIENT_PACKET" --root cholla-history --commit
   "$COMMIT" --out "$NEW_DESTINATION"`, plus the shared options above.

6. In each **disposable restored output**, use independently controlled native
   Git/LFS checks: exact HEADs, full fsck, exact recursive submodule status, index
   flags, cached and worktree diffs, empty porcelain status including untracked
   files, and LFS fsck. Inspect committed pointer blobs independently and hash each
   hydrated file against the JSON's per-rehearsal path/size/SHA-256 expectations.
   Do not derive expected bytes solely from the production manifest or checker.
7. Exercise `explain` for a historical dependency and a requiring payload and
   compare its immediate parent/gitlink edges and LFS occurrence to the independently derived requiring root/child/path relationship. `explain` returns immediate inclusion reasons; repeated queries may be needed to walk to a selected root. In an owned
   disposable packet copy, remove the required payload
   `bd88a93979a85d1c75ef28d31c1cb5f0f7014200488a560746934f471addd730`.
   Verification/restore must block before final output; preserve the intact tested packet.
   The damaged copy may fail the exact artifact-layout check before semantic
   recomputation, so its manifest chain must not be reported as verified. Use
   the separately verified intact explanation to identify the missing payload
   relationship. This distinction avoids turning damaged manifest text into evidence. Original native evidence found this
   failure under root `988e4c5b…` and child `e8fc667a…`.
8. Rehash every original source regular file, compare paths/counts/hashes with the
   before snapshot, and report the exact rehearsed commit list. Three rehearsals
   never mean every included root ancestor was executed.

## Repeat the fair native baseline

The historical `public-native-comparison.py` and companion scripts are identified
by SHA-256 in the JSON. Do not rerun them verbatim: they used PATH tools, old LFS,
and some original-source native reads. Repeat their substantive experiment on
clean disposable stages using the qualified binaries and fixed configuration:

1. Archive both complete frozen bare source stores and the **same required cache**
   using one recorded tar/gzip implementation and options. No extra current LFS
   payloads, worktrees, or invented cache bloat belong in this baseline.
2. Independently enumerate all selected root ancestors and historical gitlinks.
   In fresh stages, retain the selected root seed and the six exact child seeds
   as fixed tool-owned refs. Set each staging HEAD to a valid seed ref before
   creating native full bundles; the initial experiment failed when staging HEAD
   was unresolved. Verify both bundles with native Git.
3. Copy the same 11 validated payloads beside those two bundles and a small
   reference manifest. Archive with the same tar/gzip command family as step 1.
4. Restore all three root revisions from the full-store archive and from the
   selected bundles/cache using only disposable copies. Perform the independent
   postconditions above. The reference may use native LFS checkout in its owned
   outputs; HistoryCrate production must not use `lfs checkout`, `pull`, `fetch`,
   or `install`.
5. Extract the selected archive into another owned directory, compare all member
   bytes, and perform three additional restorations. Rehash original source files.
6. Report both archive and regular-file sizes, bundle sizes, exact tool identities,
   compression options, timings, sampled resources, and any difference in source
   inventories. Compare the implemented HistoryCrate packet separately; never
   relabel the old native selected archive as HistoryCrate output.

Original recorded measurements:

| Quantity | Bytes |
|---|---:|
| Both complete stores, regular files | 111,849,478 |
| Native selected packet, regular files | 48,983,367 |
| Complete-store `.tar.gz` | 86,030,778 |
| Native selected `.tar.gz` | 23,427,766 |
| Root native bundle | 19,978,471 |
| Child native bundle | 13,299 |
| Same cache used by both methods | 28,989,160 |

The 72.8% compressed reduction is from selected Git history and repacking. LFS
cache savings were zero. Complete-store copying is simpler to create manually
and preserves additional current history. These old values are reference measurements only. The actual patched-runtime HistoryCrate packet comparison is 51,204,224 regular-file bytes / 24,129,771 compressed bytes versus 111,849,478 / 86,034,930 for full stores, measured with the same cache and streaming archive method. That is 71.95% compressed reduction, with zero LFS-cache savings. Human usability and a repeated patched native-bundle baseline remain unmeasured.

## Scale blockers found by source inspection

These are historical findings from stage-3–5 inspection on 2026-10-19, before packet/restore completion. Later reviewed packed staging and bounded parsed-object caching addressed them without raising limits. The actual completed timings and observations are in `qualification.md`; the discussion below explains the original concerns, not the final implementation state.

### Shared 4,096-entry threshold

`Limits.observation_entries` is 4,096. Source inventory and scratch observation
both consume this same ceiling; the process/thread observer also has an explicit
4,096 maximum. The source packs currently occupy far fewer entries, so acquiring
the existing packed stores does **not** itself hit this ceiling.

However, materializing one loose file per selected Git object requires at least
15,402 files, before directory fanout, caches, worktrees, or logs. Such staging
will fail scratch observation. Splitting files into subdirectories does not fix
the total recursive count. A boundary test must cover this before a full run.

Preferred bounded design: keep the selected object set packed, emit it through a
bounded native pack stream in controlled staging, and verify exact membership.
This avoids increasing any existing threshold. If loose-object staging is an
intentional requirement, propose and review a separate filesystem-entry limit
with explicit source/scratch accounting and observation time bounds. Keep the
4,096 process/thread cap unchanged. That is a documented profile amendment, not
a per-user limit increase, and needs lowered-boundary, timeout, and refusal tests.

### Per-object commands and repeated traversal

At inspection, `ObjectReader.read`, `commit`, and `tree` invoke a fresh framed
`cat-file --batch` process per object. `info` caches verified metadata, but parsed
commit/tree bodies are not cached. Closure traversal reads a commit again in
`walk_tree` and `read_gitmodules`, traverses shared historical trees repeatedly,
and evaluates attributes per commit. Ordinary conversion performs checkout and
hash in two native commands per uncached `(repository, blob, path, attributes)`.
The root selection has 6,273 distinct trees and 6,560 remaining blob objects
after subtracting 2,518 commits from its 15,351-object bundle. Repeated paths can
produce more conversion keys than distinct blobs.

Native commands perform process/scratch observations and retain records;
`CopyMonitor.check` also performs complete observations each time. Thus process
startup, repeated traversal, observations, and retained diagnostic data can
dominate a real run even though its byte sizes are small. At that earlier inspection, no exact runtime or failure point had been measured. Do not raise the frozen 1,800-second job
budget or silently skip round-trip/attribute checks to claim success.

Narrow improvements for review and tests:

- Cache verified parsed commit/tree objects within an immutable acquired store,
  with explicit byte/count accounting and eviction; cached semantic reuse must
  still charge every historical commit-path visit.
- Support bounded multi-object framed reads with independently checked OIDs,
  types, declared sizes, SHA-1s, ordering, completion, and total streamed bytes.
  Keep one native process at a time, existing deadlines, and refusal on extra,
  missing, truncated, or malformed frames.
- Reuse tree/attribute results only when the complete committed attribute context
  and path semantics are identical; changed ancestor `.gitattributes` must
  invalidate reuse. Preserve historical mapping and provenance checks.
- Rate-limit repeated *samples*, with cheap deadline checks between bounded
  controller chunks and explicit preallocation/postmaterialization checks.
  Report actual observation gaps and fail closed on incomplete observations.
- Bound retained command/sample reports while keeping required diagnostics and
  maxima. Repeated raw argv and samples must not become unbounded hidden memory.

Re-run original correctness/refusal/native tests after changes, then execute the
entire Cholla workflow under the unchanged selected profile. If compatibility,
resource limits, or timing still block the full fixture, preserve the exact
failure and report the release gate as blocked.

## Opt-in acceptance harness

The source distribution includes `tests/external/qualify_cholla.py`. It never downloads the fixture or runs Cholla code. Missing inputs are a failure, not a skipped test. After separately preparing the pinned trusted stores and exact required cache, use a private owned output parent outside this source tree and outside the input stores:

```sh
PYTHONPATH=src python tests/external/qualify_cholla.py --run \
  --git-dir "$CHOLLA_GIT_DIR" \
  --data-git-dir "$CHOLLA_DATA_GIT_DIR" \
  --lfs-objects-dir "$CHOLLA_LFS_OBJECTS_DIR" \
  --output-parent "$CHOLLA_QUALIFICATION_OUTPUT_PARENT" \
  --git "$HISTORYCRATE_GIT" --git-lfs "$HISTORYCRATE_GIT_LFS"
```

The driver calls the real packet-creation API, then verifies a separate recipient packet in a fresh Job and restores the three pinned revisions. Negative CLI checks run in fresh interpreters so retained harness memory does not interfere with doctor’s deliberately lowered observer self-test. A narrowly scoped `--continue-from` mode admits only the recorded post-API negative-test failure boundary and revalidates all bound evidence before running the negative/compression tail; it does not resume or repeat production phases. It labels this as API qualification; the mandatory original-fixture suite independently tests the CLI. Its native oracle copies only object data into clean repositories, derives exact native object/commit/gitlink/LFS sets from pinned IDs, and compares them with the actual packet. Restored outputs are admitted by inert configuration inspection before ordinary native Git checks without command-line configuration overrides. Every tracked regular file's mode, checkout bytes and clean hash are checked, as are index flags, exact LFS worktree/cache bytes, native diffs/status and recursive submodule status. Original source file hashes are rechecked on success or failure.

The generated report and raw native logs remain in the chosen private output directory. They may contain local paths and complete research data; do not include that directory in a release. The same streaming tar/gzip method measures the actual HistoryCrate packet and both complete frozen stores with the same required payload cache. Archive bytes are observations for that run, not fixed acceptance thresholds. Consult `qualification.md` for the actual completed coverage of this candidate.
