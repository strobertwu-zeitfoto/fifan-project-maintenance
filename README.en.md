# Fifan Project Maintenance

<img src="docs/images/mascot.png" width="192" height="128" alt="An AI file-folder mascot wearing a nurse cap with a red cross" />

**Project maintenance for Vibe Coding. Automation scripts handle most repetitive checks and mechanical file operations.**

Let AI read less unrelated material and focus on development.

[简体中文](README.md) · English · [www.fifanlabs.com](https://www.fifanlabs.com)

<details open>
<summary>Plain language: what does this do for me?</summary>

| Check your project | Slim active documents | Scripts first, AI judgment next |
| --- | --- | --- |
| Find broken links and reference problems | Shorter current instructions, retained history | Inspect in batches, read relevant passages |

<img src="docs/images/workflow-zh.png" width="900" height="600" alt="Workflow: you define the maintenance scope; the AI folder nurse interprets relevant information; a robot runs deterministic scripts; the AI reviews results. Historical and recovery records are retained where supported. Changes and deletion require authorization." />

The illustration is in Chinese. Its four steps are **your request → AI interpretation → script automation → result review**.

### Recorded outcomes

| Scenario | Outcome |
| --- | --- |
| One real-project Markdown guide | **41.5 KB → 4.9 KB**, 88.1% less active text |
| 13 important real-project documents | **794.6 KB → 209.0 KB**, 73.7% less active text |
| 20,005 historical files in a synthetic test | Metadata inspection with **zero body bytes read** |

These November 2026 cases include tool-and-Agent collaboration and labeled synthetic tests. Historical originals are retained separately. The figures are not measured token-saving percentages. [Details and measurement boundaries](docs/CASE_STUDIES.md)

Try asking your Agent:

> Check this project's important instructions and plans. Report problems first without modifying files. Inspect historical files with scripts, and read their contents only when a finding needs investigation. Keep reading and output small.

Mechanical checks make no model calls. Agent orchestration, interpretation, and editing still use your allowance. Application bugs need appropriate code review and runtime tests.

</details>

<details>
<summary>Technical introduction: features, installation, and support</summary>

The local CLI provides document, link, configuration, dependency, asset, and evidence checks; bounded reading; precise change previews; journals; multi-batch recovery; directory inspection; search-view maintenance; same-volume archiving; and explicitly approved cleanup.

### Installation

Python3.12 is recommended. From the repository directory:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
./bin/fifan-maintain --version
```

```bash
./bin/fifan-maintain check \
  --project /absolute/path/to/project \
  --files README.md \
  --preflight

./bin/fifan-maintain check \
  --project /absolute/path/to/project \
  --files README.md \
  --format summary
```

Installation may require network access; project checks run offline. The tool does not run target-project scripts/plugins or launch Unity. Archival/cleanup occupancy checks require lsof; search validation requires rg. Missing capabilities are reported, not automatically installed.

### Agent compatibility

**The CLI is model-independent and can be integrated with Agents that can run local commands.** The companion Skill follows a Codex workflow and requires configuration of the actual installation path. Other Agent products have not been individually validated; browser-only Agents without local command execution cannot invoke it directly.

### Platform and safety

- Python3.9 minimum; Python3.12 recommended/default. Validated on Intel macOS with3.9.6,3.12.14, and3.15.2.
- Some controlled operations use macOS-specific APIs. Windows, Linux, Apple Silicon, and free-threaded Python have not been validated.
- Inspection is read-only by default. Changes, archiving, and cleanup require explicit scope and authorization. Permanent deletion is irreversible.
- Directory descriptors, fingerprints, and cooperative locks do not prevent every concurrent external write; pause other editors during changes.
- Keep reports, plans, and recovery material outside the target project as required; protect project text and credentials.

</details>

## Documentation

Detailed command documentation is primarily in Chinese.

- [Usage](docs/USAGE.md) · [Agent Skill](skill/SKILL.md)
- [Validation](docs/VALIDATION.md) · [Testing](docs/TESTING.md)
- [Dependencies and notices](docs/DEPENDENCIES.md) · [License status](NOTICE.md)

The maintainer has not selected a project license. Third-party notices are retained. Website: [www.fifanlabs.com](https://www.fifanlabs.com).
