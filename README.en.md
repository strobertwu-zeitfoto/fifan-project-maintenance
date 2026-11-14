# Fifan Project Maintenance

Feature version **1.5.0** adds opt-in bounded reference batches/resume, reference review packs, explicit generated-build disposal, read-only joint navigation/archive previews, and literal preservation/binding advice. See [upgrade guide](docs/UPGRADE_1_5.md), [changelog](docs/CHANGELOG.md), and [validation scope](docs/VALIDATION.md). Legacy commands and profiles retain their default behavior.

<img src="docs/images/mascot.png" width="192" height="128" alt="An AI file-folder mascot wearing a nurse cap with a red cross" />

**Project maintenance for Vibe Coding. Automation scripts handle most repetitive checks and mechanical file operations.**

Let AI read less unrelated material and focus on development.

[简体中文](README.md) · English · [www.fifanlabs.com](https://www.fifanlabs.com)

## Download 1.5.0

| Download | Contents |
| --- | --- |
| **[Full toolkit ZIP (recommended)](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/download/v1.5.0/fifan-project-maintenance-1.5.0.zip)** | CLI source, Skill, documentation, examples and tests; Python/environment not bundled |
| [Companion Skill ZIP](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/download/v1.5.0/fifan-project-maintenance-skill-1.5.0.zip) | Agent guidance; requires the CLI and its actual local path |
| [Python wheel](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/download/v1.5.0/fifan_project_maintenance-1.5.0-py3-none-any.whl) | For an existing Python environment; installing dependencies may need network access |
| [SHA-256 checksums](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/download/v1.5.0/SHA256SUMS) | Verify the three files above |

**[Installation](INSTALL.md#english-quick-start)** · [Release notes](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/tag/v1.5.0) · [Latest release](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/latest)

Recommended: macOS and Python 3.12. This is a local command-line toolkit; an Agent with local execution can install and operate it. See [validation scope](docs/VALIDATION.md).

## What does this do for me?

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


## Technical details

The local CLI provides document, link, configuration, dependency, asset, and evidence checks; bounded reading; precise change previews; journals; multi-batch recovery; directory inspection; search-view maintenance; same-volume archiving; and explicitly approved cleanup.

### Core capabilities and responsibilities

| Module | Automation scripts | Agent |
| --- | --- | --- |
| Document and reference checks | Check documents, links, and anchors; record issues and coverage gaps | Assess impact on the current task and decide how to fix issues |
| Configuration, dependencies, assets, and evidence | Check format, references, size, and signs of duplication against rules | Assess business meaning, retention value, and what needs further validation |
| Important Markdown maintenance | Bounded reading, change previews, precise writes, operation journals, and recovery verification | Retain active requirements, merge duplicate explanations, and distinguish current from historical content |
| History and directory maintenance | Inventory metadata, check search scope and references, and archive on the same volume | Select key directories and confirm archival eligibility; do not delete solely because no references were found |
| Safe cleanup prerequisites | Check old artifacts for eligibility, preview, quarantine, verify, and rebuild the baseline after cleanup | Confirm purpose and authorization; handle eligible cleanup first, then maintain retained material |
| Results and cost control | Enforce read/output budgets; summarize findings, actual changes, and unknowns | Read relevant highlights and explain results; do not invent model usage or savings percentages |

These capabilities are available on demand through one local CLI entry point, without requiring a persistent service, scheduled tasks, or Hooks. Scripts provide mechanical evidence; they do not replace business-code review, tests in the actual host, or user acceptance.

### Architecture: judgment and automation

The Agent and Skill interpret relevant material, decide what must be retained, and submit explicit requests. The local CLI and scripts perform bounded inspection, reading, previews, changes, and verification. The automation layer makes no model calls; scope, budgets, fingerprints, and cooperative locks constrain operations.

The architecture and swimlane diagrams below show the workflow and its safety boundaries. The architecture separates user authorization, Agent judgment, local automation, shared safeguards, project files, and external operation records.

```mermaid
flowchart TB
    U["User<br/>Set goals and authorization scope"]

    subgraph AI["Judgment layer: Agent software + companion Skill"]
        A["Understand requirements and material<br/>Assess active requirements, conflicts, and retention value"]
        Q["Create explicit tasks<br/>Specify files, budgets, change requests, and approved scope"]
        A --> Q
    end

    U --> A

    subgraph LOCAL["Local automation layer · Python 3.12 by default"]
        CLI["Unified CLI entry point<br/>fifan-maintain"]

        CHECK["Mechanical checks<br/>Documents, links, configuration, dependencies, assets, etc."]
        WORKER["Inspection subprocesses<br/>Run with time limits; summarize findings and coverage"]

        FILE["Document maintenance<br/>Bounded reading, change previews, precise writes, multi-batch recovery"]
        DIR["Directory maintenance<br/>Inventory, search scope, reference checks, archiving and recovery"]
        FLOW["Cleanup prerequisites<br/>Assess old artifacts first, then maintain retained material"]
        CLEAN["Safe cleanup<br/>Eligibility checks, preview, quarantine, recovery<br/>Permanent deletion requires separate approval"]

        CLI --> CHECK --> WORKER
        CLI --> FILE
        CLI --> DIR
        CLI --> FLOW --> CLEAN
        FLOW -->|"Rebuild baseline after cleanup"| CHECK
        FLOW -->|"Run declared follow-up tasks"| FILE
        FLOW -->|"Run declared follow-up tasks"| DIR
    end

    Q --> CLI
    U -->|"Can also use the CLI directly"| CLI

    subgraph GUARD["Safety constraints across workflows"]
        S["Exact scope and protection rules · Read and output budgets<br/>File fingerprints and drift checks · Directory FDs and cooperative locks"]
    end

    S -.-> CHECK
    S -.-> FILE
    S -.-> DIR
    S -.-> CLEAN

    P[("Target project<br/>Current documents, source, configuration, assets, historical files")]
    R[("Authorized directories outside the project<br/>Plans, operation records, archives, quarantine and recovery material")]
    O["Result feedback<br/>Findings, actual changes, size metrics<br/>Passed, failed, and unconfirmed items"]

    WORKER --> O
    FILE <-->|"Controlled reads and writes"| P
    DIR <-->|"Controlled operations"| P
    CLEAN <-->|"Exact approved targets"| P
    WORKER -->|"Controlled reads"| P

    FILE --> R
    DIR --> R
    CLEAN --> R
    FILE --> O
    DIR --> O
    CLEAN --> O
    O -->|"Return only necessary results for judgment"| A

    classDef human fill:#eee8ff,stroke:#8062ad,color:#302443;
    classDef automation fill:#e4f4e8,stroke:#53846a,color:#183d2b;
    classDef storage fill:#fff0ce,stroke:#bd9042,color:#503818;
    classDef guard fill:#ffebe2,stroke:#c68364,color:#593524;
    class U,A,Q human;
    class CLI,CHECK,WORKER,FILE,DIR,FLOW,CLEAN,O automation;
    class P,R storage;
    class S guard;
```

### Signature workflow: slimming important Markdown documents

Scripts inspect first, then the Agent requests only relevant passages. A precise change request goes through permission, fingerprint, and retention checks before preview and authorized execution. Snapshots and journals support applicable recovery operations. Changed files or failed conditions stop the request; restoration also checks the current state and refuses to overwrite later edits. Permanent deletion is irreversible.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant A as Agent + Skill
    participant S as Local automation scripts
    participant P as Project documents
    participant R as Archives and operation records

    U->>A: Identify key documents and authorize maintenance within scope
    A->>S: Inspect scope, size, structure, and references
    S->>P: Read necessary metadata and inspection material
    S-->>A: Return issue summary, outline, and coverage

    rect rgb(238, 246, 238)
        Note over A,P: Inspect mechanically first, then read on demand to reduce irrelevant AI context
        A->>S: Request relevant sections or excerpts
        S->>P: Read within permissions and budgets
        S-->>A: Return bounded excerpts
        Note over A: Assess active requirements, historical content, and information that must be retained
    end

    A->>S: Submit precise changes, retention assertions, and archival arrangements
    S->>P: Check permissions, source fingerprints, and retention conditions

    alt Files changed or checks failed
        S-->>A: Reject stale request, leave originals unchanged
        A-->>U: Explain blockers and material requiring reinspection
    else Preflight passed
        S-->>A: Return change preview and size baseline
        A->>S: Execute authorized changes
        S->>R: Save operation intent and necessary original snapshots
        S->>P: Apply precise changes
        S->>R: Save operation journal and recovery material

        S->>P: Read back, verify retention conditions and references
        S-->>A: Return text changes, archive growth, and verification results
        A-->>U: Report actual benefits and unconfirmed issues
    end

    opt Recovery needed later
        U->>A: Request recovery
        A->>S: Preview recovery and check current state
        Note over S,P: Refuse to overwrite later edits
        S->>R: Read recovery material when conditions are met
        S->>P: Restore and verify again
        S-->>U: Return recovery result
    end
```

Active text reduction, archive growth, and external records are measured separately. Moving bytes is not total project shrinkage, and fewer bytes are not a measured token-saving percentage.

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
- Some controlled operations use macOS-specific APIs. Version 1.5.0 has synthetic regression evidence on Apple Silicon/Python 3.12 (see Validation); Windows, Linux, free-threaded Python and real business-project acceptance remain unvalidated.
- Inspection is read-only by default. Changes, archiving, and cleanup require explicit scope and authorization. Permanent deletion is irreversible.
- Directory descriptors, fingerprints, and cooperative locks do not prevent every concurrent external write; pause other editors during changes.
- Keep reports, plans, and recovery material outside the target project as required; protect project text and credentials.


## Documentation

Detailed command documentation is primarily in Chinese.

- [Usage](docs/USAGE.md) · [Agent Skill](skill/SKILL.md)
- [Validation](docs/VALIDATION.md) · [Testing](docs/TESTING.md)
- [Dependencies and notices](docs/DEPENDENCIES.md) · [License status](NOTICE.md)

The maintainer has not selected a project license. Third-party notices are retained. Website: [www.fifanlabs.com](https://www.fifanlabs.com).
