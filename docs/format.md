# Packet format, version 1

A packet is an owned directory with exactly:

- `manifest.json`: canonical UTF-8 JSON, sorted keys, compact separators, integer numbers, no BOM or trailing newline
- `COMPLETE.json`: canonical completion record binding every artifact's relative path, byte count and SHA-256 digest
- `repos/<repository-id>.bundle`: one prerequisite-free version-2 SHA-1 Git bundle per included repository
- `lfs/objects/<first-two>/<next-two>/<sha256>`: exactly the required distinct nonempty LFS payloads

The manifest declares the `trusted-local-v1` profile, root groups and their complete parent ancestry, repository identities and demanded seeds, commit records, Git object inventory, historical gitlinks, LFS occurrences, deduplicated payload inventory and counts. Historical URL identities are SHA-256 digests. Literal URLs are reconstructed from actual committed `.gitmodules` during verification; they never authorize a fetch.

Only `refs/historycrate/commits/<full-oid>` seed refs appear in bundle headers. Fresh import repositories use a detached HEAD at a validated seed. Original refs, configuration, hooks, reflogs and incidental caches are not packet artifacts. Extra files, extra directories (apart from the prescribed empty LFS layout), aliases, symlinks, noncanonical JSON and unknown fields fail closed.

Artifact hashes are necessary but insufficient. Verification copies the packet to private owned staging, checks exact layout/hashes, imports into fresh repositories, runs native integrity checks, compares exact bundle object sets, recomputes complete historical closure and validates every required payload. Builder caches are not reused. Original packet bytes are checked again before any output publication. A packet is not authenticated: receive it only through a separately trusted channel.

Publication copies validated bytes into a private sibling, rechecks inputs and destination identity, fsyncs files/directories and uses atomic no-replace rename. The rename is the commit point. Later failures preserve the output and report `published-durability-uncertain`; never overwrite that destination on a blind retry. Packets do not contain a restore checkout. Each restored revision is independently materialized and checked; structural verification alone makes no all-revisions checkout claim.
