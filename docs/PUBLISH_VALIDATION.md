# Publication validation / 公开版本验证


## 1.5.0 — 2026-11-14

本版本提供 GitHub Release 下载。维护功能源码与已验证的本机1.5.0相同；本次仅新增发布打包辅助脚本、专项测试及公开文档，不改变48个维护运行模块。

| Check | Result and scope |
| --- | --- |
| Maintenance regression | **1104 passed / 105.62s**, Apple Silicon macOS, Python 3.12.16, fixed dependencies, synthetic projects only. Existing valid evidence is reused; no claim of a new GitHub CI run. |
| Release packaging tests | **39 passed**. Deterministic source/Skill ZIPs, checksum coverage, wheel identity, exclusions, path/overwrite rejection and drift. These are additional targeted tests, not a newly claimed combined full-suite count. |
| Runtime identity | All **48 Python modules** in the existing wheel are byte-identical to the validated source. No new runtime dependency or model service. |
| Local installed CLI | Version and distribution metadata 1.5.0; **15 temporary CLI steps passed** after installation. |
| Source ZIP installation | The final ZIP was extracted into a fresh temporary directory with a space in its path. Environment creation, installation, dependency check, executable launcher, Skill validation and **15 synthetic CLI steps passed**. |
| Independent review | 1.5 maintenance changes received scoped static NoMustfix after fixes. Release tooling/content checks are recorded separately before publication. |
| Public artifacts | Source ZIP, companion Skill ZIP, original Python wheel and SHA256SUMS. Environment, local logs, credentials, business data and machine-specific deployment driver are excluded. |

The wheel contains the CLI and pinned dependency declarations; it does not bundle Python, the full source documentation or the Skill. See [INSTALL](../INSTALL.md). Source/Skill ZIP metadata and ordering are deterministic; archives do not contain .git or virtual environments. Raw host-specific logs remain private. Filesystem guards and automated tests do not authorize maintenance of a particular real project.

### Release verification

The [v1.5.0 Release](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/tag/v1.5.0) is published and marked Latest. Source and Skill ZIPs, wheel and SHA256SUMS were downloaded back from GitHub and matched the tested local files byte for byte. All four public asset URLs returned HTTP200 at publication. The source ZIP/tag target commit is 9766eda99b56b634eebcfe6d8672d0bfeaae3b10; later publication-record edits do not move that tag.

The standalone Skill includes the unchanged NOTICE, dependency document and third-party license files, so its declaration links resolve inside the extracted package. The maintainer's project license remains unselected; [NOTICE](../NOTICE.md) is retained. Checksums establish file equality; raw host logs remain private.

## Historical 1.4.2 public snapshot

Validated on 2026-11-12 for version **1.4.2**, using **Python 3.12.14 on Intel macOS (x86_64)**. This document describes the prepared public source snapshot; repository visibility and publication are separate checks.

| Check | Result and scope |
| --- | --- |
| Public unit-test suite | **995 passed**, 0 failures, 0 errors, 0 skipped. The pytest log reports 413.57 seconds; the corresponding JUnit XML contains 995 test cases. |
| Independent environment | A fresh virtual environment installed the built 1.4.2 wheel and pinned dependencies. `pip check` reported no broken requirements. |
| Package identity | Installed distribution metadata identifies the same wheel SHA-256 shown below. Imports resolve inside the independent environment. |
| Runtime source | All **42 Python runtime modules** match the original development source and built wheel byte for byte. |
| Public test adaptation | One legacy test launcher default was changed from a maintainer-specific environment to `bin/fifan-maintain`. Other included test and tool source files are unchanged. |
| Publication filtering | The closed publication list excludes virtual environments, raw validation artifacts, private business material, project bindings, the internal engineering plan, and the project-specific retirement helper with its 23 tests. |
| Documentation preparation | Local-link existence and selected-file privacy/credential-pattern checks passed during preparation. These checks do not establish external website availability or complete security assurance. |

Built wheel: `fifan_project_maintenance-1.4.2-py3-none-any.whl`

```text
SHA-256: 7aa4af1f22e9e5aa597c6ffb33c1d3258072d717f1faf0f88ee8121950c1c27b
```

The wheel is validation evidence, not a bundled downloadable release. Raw local logs and XML are retained privately because they include machine paths and host information. Public documentation changes after the test run do not change the tested runtime modules; the final publication manifest is checked separately before upload.

## Boundaries

- **995 is the historical 1.4.2 public-suite result.** The historical 1007-test development run described in [VALIDATION](VALIDATION.md) used a different candidate and included private retirement-helper tests. It is not the count for this public snapshot.
- This public snapshot has not received a new full-suite run on Python 3.9 or 3.15. Historical compatibility evidence remains scoped to its original candidates.
- For that 1.4.2 snapshot, Windows, Linux, Apple Silicon, free-threaded Python, and other Agent products had not been validated. The 1.5.0 Apple Silicon scope is listed above. Some guarded filesystem operations use macOS-specific APIs.
- Automated fixture tests do not establish safe authorization for a particular real project, prevent every concurrent external write, or replace application runtime tests and user acceptance. Permanent deletion is irreversible.
- The project's own source and generated illustrations have **no selected project license**. Third-party notices remain included; see [NOTICE](../NOTICE.md) and [DEPENDENCIES](DEPENDENCIES.md).
- Those historical validation results did not cover tag, release, package-index publication or website deployment; the current 1.5.0 publication is recorded separately above.

中文摘要：本次公开源码候选在独立 Python 3.12.14 环境通过 995 项测试；42 个运行模块保持原始字节。旧版测试数不作为本次成绩，其他平台及本次未重跑的 Python 版本不扩大宣称。公开可见性和网页图文需在上传后另行核实。
