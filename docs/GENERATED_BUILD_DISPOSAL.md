# Explicit disposal of generated builds with incomplete provenance

The normal `old_build` contract still requires complete platform, branch,
configuration and purpose metadata, plus a retained build in that same group.
It remains the default and is unchanged for existing profiles/requests.

An independently approved generated distribution can use a narrower, explicit
loss contract when historical build metadata is unavailable. Both declarations
are required:

```json
// Exact profile candidate (JSON files themselves must not include comments):
{"path":"builds/retired-web","kind":"old_build","disposal_policy":"generated_artifact"}

// Matching request item additions:
"generated_disposal": {
  "generated_only": true,
  "reason": "Approved exact generated distribution; no unique source or evidence"
}
```

The normal request still supplies exact source/kind, closure and SHA-bound
closure evidence, reason, loss declaration and retained list. This route requires
`loss.accepted=true` and `loss.unique_evidence=false` even to quarantine. The
attestation applies only to the exact approved candidate; rules/globs cannot
approve a new candidate. It is an explicit operator declaration, not automatic
proof that a folder is generated.

`build` may be absent or contain the historical fields actually known; unknown
values may remain `Unknown`. The report lists `build_provenance.status=Unknown`
and every missing field, retaining the provided metadata. That informational
provenance gap does not block the separately approved disposal contract. The
report/material explicitly record
`retention_comparison=WaivedByExplicitLossApproval`; no replacement build,
rebuildability, source provenance, runtime validation or user acceptance is
invented. Any separately listed retained objects still receive the normal checks.

Use the existing preview, exact-plan approval, quarantine, verify, restore,
re-preview, and separately approved purge commands. An inspection or this profile
field alone never deletes anything. Purge still requires the explicit purge
action, item disposition, accepted loss, exact plan approval and all native gates.

Formal source roots, current/keep/reference originals, explicit protection,
production/save/database formats, aliases, symlinks, hard links, occupied files,
source or profile drift, cooperative locks and recovery remain protected. Packaged
runtime code is handled only through the existing exact `old_build` subtree
contract; this feature does not turn source files into disposable output.
