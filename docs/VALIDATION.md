# 验证与限制 / Validation and limitations

Version1.4.2 retains Python>=3.9 compatibility. The project launcher recommends/defaults toPython3.12; the maintainer's validated interpreters are3.9.6,3.12.14,3.15.2 on Intel macOS.

## Existing development evidence

- A complete installed-package Python3.15 run passed1007 tests. The final retirement-helper tests subsequently grew from16 to23 and were rerun separately;991 unchanged nodes plus23 final nodes matched1014 collected nodes exactly. There was no single1014-test full XML.
- Affected Python3.9 and3.12 suites each passed529 tests. Runtime protection checks each passed25; retirement-helper tests each passed23. A post-cleanup suite passed61.
- Default-launcher selection later changed to3.12:17 real-shell tests passed on each interpreter;58 CLI tests passed on3.12. Real default execution, explicit315/39 selection, two official wrappers, and v3 preview/apply/verify/recover passed.
- Real1.4.1 records generated on3.9 were verified/restored by1.4.2 on3.15, covering file/session/directory/search/cleanup state. Another3.12 state round trip passed after the default switch.
- Directory/archive checks include real restoration of7,346 controlled files, failures, source drift, path aliases, subprocess interruption, and recovery boundaries. Metadata-only tests keep uncovered work Unknown.

These raw historical artifacts contain local paths and project data, so they are retained privately rather than shipped in this repository. Counts describe those specific candidates. The public snapshot omits the project-specific retirement helper and its23 tests; public-source validation is recorded separately in PUBLISH_VALIDATION.md after preparation.

## Important limits

- Some descriptor/canonical-path and exclusive-rename operations are macOS-specific. Windows/Linux/Apple Silicon/free-threaded builds have not been validated.
- Source/config existence and an exit code do not alone prove healthy content. Inspect coverage, findings, truncation, and Unknown/Not run states.
- Cooperative locks do not stop every external writer; pause other editors for changes. Occupancy checks are samples.
- Content backups do not recreate original inode history. Permanent purge is irreversible and requires its own explicit authorization.
- Filesystem size, logical deletion bytes, token use, and system free-space changes are distinct measurements.
- File-operation checks do not replace application runtime tests or user acceptance.

This tool does not execute target-project scripts/plugins, call models, or launch Unity. Agent software used to interpret results has its own permissions and usage costs.
