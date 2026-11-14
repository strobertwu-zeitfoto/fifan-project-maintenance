# 验证与限制 / Validation and limitations

## 1.5.0 验证（2026-11-14）

Apple Silicon macOS、Python 3.12.16、固定依赖，维护功能完整回归 **1104 passed / 105.62s**。验证仅使用临时合成工程，覆盖分批/续办/漂移、原生归档/恢复、生成物隔离/恢复/purge、联合预演和字面 advisory。独立静态复核最终为限定 NoMustfix；运行包48个Python模块与已测源码、wheel及独立环境一致。

复现命令（在源码根，先按开发测试说明安装固定测试依赖）：

```bash
PYTHONDONTWRITEBYTECODE=1 FIFAN_MAINTAIN_RUNTIME=312 \
  FIFAN_MAINTAIN_TOOL="$PWD/.venv/bin/fifan-maintain" \
  .venv/bin/python -B -m pytest -q -p no:cacheprovider
```

本机部署另有17个临时场景，安装后15个临时CLI步骤通过；本机部署驱动、完整日志和恢复材料不包含在公开包中。这些本机结果不等同真实业务工程、所有平台或用户接受。下载产物与发布辅助测试见 [公开验证](PUBLISH_VALIDATION.md)。

Version1.4.2 retains Python>=3.9 compatibility. The project launcher recommends/defaults toPython3.12; the maintainer's validated interpreters are3.9.6,3.12.14,3.15.2 on Intel macOS.

## Existing development evidence

- A complete installed-package Python3.15 run passed1007 tests. The final retirement-helper tests subsequently grew from16 to23 and were rerun separately;991 unchanged nodes plus23 final nodes matched1014 collected nodes exactly. There was no single1014-test full XML.
- Affected Python3.9 and3.12 suites each passed529 tests. Runtime protection checks each passed25; retirement-helper tests each passed23. A post-cleanup suite passed61.
- Default-launcher selection later changed to3.12:17 real-shell tests passed on each interpreter;58 CLI tests passed on3.12. Real default execution, explicit315/39 selection, two official wrappers, and v3 preview/apply/verify/recover passed.
- Real1.4.1 records generated on3.9 were verified/restored by1.4.2 on3.15, covering file/session/directory/search/cleanup state. Another3.12 state round trip passed after the default switch.
- Directory/archive checks include real restoration of7,346 controlled files, failures, source drift, path aliases, subprocess interruption, and recovery boundaries. Metadata-only tests keep uncovered work Unknown.

These raw historical artifacts contain local paths and project data, so they are retained privately rather than shipped in this repository. Counts describe those specific candidates. The public snapshot omits the project-specific retirement helper and its23 tests; public-source validation is recorded separately in PUBLISH_VALIDATION.md after preparation.

## Important limits

- Some descriptor/canonical-path and exclusive-rename operations are macOS-specific. Windows/Linux/free-threaded builds remain unvalidated. Apple Silicon evidence is limited to the 1.5.0 synthetic suite above, not business-project acceptance.
- Source/config existence and an exit code do not alone prove healthy content. Inspect coverage, findings, truncation, and Unknown/Not run states.
- Cooperative locks do not stop every external writer; pause other editors for changes. Occupancy checks are samples.
- Content backups do not recreate original inode history. Permanent purge is irreversible and requires its own explicit authorization.
- Filesystem size, logical deletion bytes, token use, and system free-space changes are distinct measurements.
- File-operation checks do not replace application runtime tests or user acceptance.

This tool does not execute target-project scripts/plugins, call models, or launch Unity. Agent software used to interpret results has its own permissions and usage costs.

## 安装核验边界

CLI与包元数据应同时为1.5.0；安装后先在临时样例检查。Skill需配置实际入口，不能凭文件存在判断已加载。旧editable环境回退须与原源文件配对，不应仅切换环境。平台及历史候选的适用边界仍按上文保留。
