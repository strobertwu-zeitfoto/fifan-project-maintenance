# Public snapshot validation / 公开候选验证

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

- **995 is the current public-suite result.** The historical 1007-test development run described in [VALIDATION](VALIDATION.md) used a different candidate and included private retirement-helper tests. It is not the count for this public snapshot.
- This public snapshot has not received a new full-suite run on Python 3.9 or 3.15. Historical compatibility evidence remains scoped to its original candidates.
- Windows, Linux, Apple Silicon, free-threaded Python, and other Agent products have not been validated. Some guarded filesystem operations use macOS-specific APIs.
- Automated fixture tests do not establish safe authorization for a particular real project, prevent every concurrent external write, or replace application runtime tests and user acceptance. Permanent deletion is irreversible.
- The project's own source and generated illustrations have **no selected project license**. Third-party notices remain included; see [NOTICE](../NOTICE.md) and [DEPENDENCIES](DEPENDENCIES.md).
- No tag, release, package-index publication, or website deployment is covered by these results.

中文摘要：本次公开源码候选在独立 Python 3.12.14 环境通过 995 项测试；42 个运行模块保持原始字节。旧版测试数不作为本次成绩，其他平台及本次未重跑的 Python 版本不扩大宣称。公开可见性和网页图文需在上传后另行核实。
