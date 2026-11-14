# Bounded reference batches

Reference batching is opt-in on cleanup and directory profiles. Profiles without
`reference_batching` retain their existing single-scan limits and failure behavior.
For example, retain the normal `budgets` and add explicit aggregate allowances:

```json
"reference_batching": {
  "max_batches": 20,
  "max_total_bytes": 536870912,
  "max_total_files": 100000,
  "max_total_seconds": 600
}
```

Every batch still enforces `max_reference_bytes`, `max_reference_files`,
`max_reference_file_bytes`, time, safe descriptor reads, protection, and aliases.
A file cannot be split to bypass its per-file allowance. Explicit streaming
log/txt grants retain their existing streaming contract. Aggregate bytes count
originals and any projected candidate bytes; files and batch count bound the
complete declared set. Metadata work, depth, and the total serialized inventory
and parse facts remain bounded by the original entry/artifact limits. The hard
aggregate ceilings are 1000 batches, 8 GiB, 1000000 files, and 3600 seconds.

`cleanup reference-estimate` and `directory reference-estimate` accept the normal
`--project`, `--profile`, optional `--request`, and external `--output`. They walk
only declared reference sources, report estimated parse and revalidation IO, and
read zero reference body bytes. Estimate success describes the planned IO, not
qualification. An inadequate budget or an incomplete inventory is rejected.

`reference-advance` accepts those same inputs plus `--max-batches` (default 1).
Use a fresh external output filename for each checkpoint. A checkpoint with more
work left reports **Partial** and incomplete coverage. Retain the printed
fingerprint separately. Continue with `--resume <previous.json>` and
`--reference-fingerprint <retained-fingerprint>`; do not take the anchor from an
untrusted edited receipt. The resume command must use the same request/scope.

Resume compares the project/profile/config, parser implementation, ordered batch
coverage and complete inventory, then freshly hashes completed files with the
same per-batch limits. It reuses their parse facts and parses only new batches.
New/removed/changed files, missing/reordered chunks, drift or a changed receipt
are rejected. A failed/interrupted call leaves earlier checkpoint files intact;
resume the last successfully written checkpoint. Work since that checkpoint is
repeated. The fingerprint is an integrity/intent binding, not an authentication
or hostile-author signature. A user-endorsed fabricated receipt is not a trusted
source of dependency truth.

Receipts are inspection-only and never authorize archive/cleanup mutations.
Preview and apply always perform their own fresh complete batched scans, and
archive reference proofs are freshly hashed in bounded batches as well. Existing
qualification, closure, protection, occupancy, drift, and recovery gates remain
required. Unknown parse results remain Unknown; complete coverage does not mean
all static/dynamic/external dependencies have been proven absent.

Coverage records actual reference bytes, fresh validation bytes, and measured
inventory, resume validation, parsing, final inventory, and overall durations.
Repeated resumes count their earlier elapsed work toward the aggregate time
allowance. Bytes/files describe the bounded input set per invocation rather
than a lifetime IO quota. Existing retained/candidate hash budgets stay separate.
