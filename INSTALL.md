# 下载安装 / Installation

## 选择下载项

从 [1.5.0 Release](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/tag/v1.5.0) 下载：

- `fifan-project-maintenance-1.5.0.zip`：推荐。包含 CLI 源码、Skill、文档、示例与测试，不含 Python、依赖或虚拟环境。
- `fifan-project-maintenance-skill-1.5.0.zip`：单独的 Agent Skill。只装它不能运行 CLI。
- `fifan_project_maintenance-1.5.0-py3-none-any.whl`：仅 Python CLI 包；适合已有环境的用户。
- `SHA256SUMS`：三个包的 SHA-256 校验值。

推荐 Python 3.12；最低兼容声明为 3.9。归档/清理需要 macOS 的受控文件系统能力及 `lsof`；搜索验证需要 `rg`。缺少这些能力时工具报告受阻，不自动安装。1.5.0 的实际测试范围见 [验证说明](docs/VALIDATION.md)。

## 完整工具包安装（推荐）

1. 下载并解压完整工具包，得到 `fifan-project-maintenance-1.5.0` 文件夹。
2. 在该文件夹打开终端，执行：

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
./bin/fifan-maintain --version
```

预期版本为 `1.5.0`。安装依赖可能需要网络；之后的项目检查离线执行。仓库克隆也可使用相同命令，进入实际克隆目录后执行即可。

先用准确范围做只读预检：

```bash
./bin/fifan-maintain check \
  --project /absolute/path/to/your-project \
  --files README.md \
  --preflight
```

将项目路径改成实际路径；不要照抄示例路径。预检不会治理或删除文件。详细命令见 [使用说明](docs/USAGE.md)。

## 安装配套 Skill

1. 使用完整包中的 `skill/`，或解压单独 Skill ZIP 中的 `fifan-project-maintenance/`。
2. 将完整内容放入 Agent 实际读取的 Skill 目录，保留 `SKILL.md` 和 `references/`。Codex 常见配置为 `~/.codex/skills/fifan-project-maintenance/`；已有 `~/.agents/skills/` 配置时沿用原目录，避免重复装同名副本。
3. 编辑该 `SKILL.md`，将 `<工具安装目录>/bin/fifan-maintain` 替换为刚才安装的 CLI **绝对路径**，例如 `/absolute/path/to/fifan-project-maintenance-1.5.0/bin/fifan-maintain`。
4. 在后续对话调用 `$fifan-project-maintenance`，并明确项目、范围与授权。

已有 Skill 时，先备份并对比更新，保留本机入口和其他自定义内容。Skill 被发现不等于获得修改或删除项目的权限。

## 仅安装 wheel

在下载 wheel 的目录执行：

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install ./fifan_project_maintenance-1.5.0-py3-none-any.whl
.venv/bin/fifan-maintain --version
```

使用 `.venv/bin/fifan-maintain` 作为 CLI；wheel 不附带仓库的 `bin/` 启动器、完整说明或 Skill。给 Skill 配置入口时使用该 console script 的绝对路径。

## 校验与升级

三个包和校验文件都放在同一目录时：

```bash
shasum -a 256 -c SHA256SUMS
```

只下载其中一个包时，用 `shasum -a 256 文件名` 计算值，对照 `SHA256SUMS` 的相应行；未下载其他包时，整份 `-c` 校验会提示缺少文件。

升级使用新的解压目录和独立 `.venv`，先验证版本和临时样例，再更新 Agent 的入口。保留旧版本及其恢复记录；不要覆盖正在运行的环境或业务工程。原环境为 editable 时，回退须同时恢复旧源码与环境。Release 不捆绑业务数据或维护记录。

## English quick start

Download the **full toolkit ZIP** from [Releases](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/releases/latest), extract it, open a terminal inside the extracted directory, and run:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
./bin/fifan-maintain --version
```

Expected version: `1.5.0`. Python and dependencies are not bundled. Dependency installation may need network access; project inspection is offline. Guarded filesystem operations require supported macOS capabilities; see [validation limits](docs/VALIDATION.md).

For the **Skill ZIP**, copy its entire `fifan-project-maintenance/` folder into the Skill directory configured in your Agent, then replace the installation placeholder in `SKILL.md` with the absolute CLI path. Preserve existing customizations. A Skill alone does not install the CLI or authorize project changes.

For a **wheel-only install**, use the wheel commands above and invoke `.venv/bin/fifan-maintain`. Verify downloaded files with `SHA256SUMS`; keep separate environments when upgrading.
