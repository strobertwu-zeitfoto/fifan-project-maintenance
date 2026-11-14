# Development tests

Use macOS with Python3.12. Version1.5.0 has Apple Silicon synthetic regression evidence; Intel results retain their historical candidate scope. From the repository directory:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
PYTHONDONTWRITEBYTECODE=1 FIFAN_MAINTAIN_RUNTIME=312 \
  FIFAN_MAINTAIN_TOOL="$PWD/.venv/bin/fifan-maintain" \
  .venv/bin/python -B -m pytest -q -p no:cacheprovider
```

Tests use synthetic fixtures, including deliberately invalid files and simulated secrets. They are not product defects to automatically repair. Some subprocess failure tests intentionally load controlled source code.

tools/run_directory_maintenance.py and tools/run_project_maintenance.py are thin production wrappers. The validate_v*.py files are development drivers; they may create large fixtures under evidence/. Start with their --help and small explicit inputs. Do not run every driver merely to install or use the tool. Historical compatibility wheels and schema-validation artifact populations are not bundled; drivers requiring them must receive valid explicit inputs.

The original project's fixed-whitelist retirement helper is excluded from this public snapshot along with its tests. It was tied to private approved paths and is not a generic deletion capability.

Use the CLI, not validator scripts, to inspect real business projects. Preserve read/write scope, private records, failure evidence, and the authorization boundary for permanent deletion.

## Release packages

Use the standard-library builder with an existing wheel whose Python module set and bytes match the source:

```bash
.venv/bin/python -B tools/build_release.py --output /absolute/external/new-release-dir --wheel /absolute/path/to/fifan_project_maintenance-1.5.0-py3-none-any.whl
```

Output must be new and outside the source. The builder exports only its closed source roots, excludes environment/evidence/credential filenames and rejects links/special files; it cannot determine whether arbitrary text in an allowed document is private. Review public content before packaging. SHA256SUMS covers exactly the three downloadable assets. Test this helper with `pytest -q tests/test_release_package.py`; this does not repeat the maintenance regression.
