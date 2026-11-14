# 使用说明 / Usage

1.5.0 新入口和兼容范围见 [升级说明](UPGRADE_1_5.md)：分批引用与续办、动态复核包、明确生成物处置、联合预演、字面保留及绑定影响。详细版本与验收状态见 [版本记录](CHANGELOG.md) 和 [工程计划](ENGINEERING_PLAN.md)。

推荐Python3.12，最低兼容3.9。官网：[www.fifanlabs.com](https://www.fifanlabs.com)。先确认真实项目、适用规则和本轮授权；不要把共同父目录当目标。

## 安装与入口

在本工具仓库目录执行：

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
./bin/fifan-maintain --version
```

依赖安装可能需要网络；项目检查离线。bin入口按.venv、.venv315、.venv39选择，始终传-B。需要其他已安装环境时使用FIFAN_MAINTAIN_RUNTIME=312|315|39；目录存在但不可用或进程失败不静默回退。直接调用console脚本时用PYTHONDONTWRITEBYTECODE=1保持同一策略。

## 先只读检查

```bash
./bin/fifan-maintain check --project /absolute/path/to/project --files README.md --preflight
./bin/fifan-maintain check --project /absolute/path/to/project --files README.md --format summary
```

--files限定准确来源，不递归；默认check选择关键文档，inventory才做显式全量机械盘点。全量机械读取不等于让Agent全文阅读。不要只凭退出码0宣称健康，查看findings、coverage、截断和Unknown/Not run。

主来源、引用正文和历史元数据可通过工程外task-profile分别授权。示例：[基础profile](../examples/task-profile.example.json)、[独立历史预算](../examples/task-profile-v2.example.json)、[项目配置](../examples/project-config.example.json)。include/exclude不是任意读取授权；保护路径优先，.env、.git、.venv/.venv39/.venv315等受保护。不要修改目标配置来绕过授权。

## 大文件按需读

```bash
./bin/fifan-maintain read --project /absolute/path/to/project --file README.md --outline --max-depth 2
```

再按实际返回的section-id、heading或lines读取必要片段；用max-output-bytes限制输出。未完成时使用返回的next_cursor和相同源/选择续读。来源变化拒绝旧游标；没有输出的部分不能算已读。

## 已授权文档修改

准确请求使用工程外JSON：

```bash
./bin/fifan-maintain preview --project /absolute/path/to/project --request /outside/request.json --plan /outside/plan.json
./bin/fifan-maintain apply --project /absolute/path/to/project --plan /outside/plan.json --operations-dir /outside/records
```

verify/recover的journal必须使用apply实际返回的路径。先核当前状态和后续修改，不能拿恢复覆盖用户的新内容。普通文件批次不是跨文件原子事务。

- [v1操作](../examples/operations.example.json)：精确replace/move；old须在原文唯一。
- [v2快照](../examples/operations-v2.example.json)：快照和正文修改进入同一日志，保留来源/分类依据与guards。
- [v3多处修改](../examples/operations-v3.example.json)：同文件patch绑定同一完整SHA，拒绝重叠/漂移；输出仍使用兼容v2执行合同。
- [locator示例](../examples/operations-v2-locator.example.json)：受控原始字节范围用于精确修改，不从脱敏展示片段反推原文。
- [归档覆盖](../examples/archive-coverage.example.json)：证明明确选区原字节已保留，不代表旧规范失效。
- [多批会话](../examples/session.example.json)：明确顺序，按recovery-preview核对逆序恢复，不按mtime猜顺序。

正文瘦身、当前视图、归档增长、恢复记录和所声明集合存储分别计量。折叠/导航不等于正文缩小，移动不等于磁盘释放；保护必要独有要求、失败与未知项。

## 目录体检与归档

需要独立directory-profile：[示例](../examples/directory-profile.example.json)、[请求](../examples/directory-request.example.json)。所有绝对根和证据SHA必须重新绑定自己的真实对象，示例不授予移动权限。

```bash
./bin/fifan-maintain directory census --project /absolute/path/to/project --profile /outside/directory-profile.json
./bin/fifan-maintain directory workflow --project /absolute/path/to/project --profile /outside/directory-profile.json --records-dir /outside/records
```

workflow默认inspect；search/archive/restore通过显式phase进入。正式薄封装tools/run_directory_maintenance.py调用同一流程，不提供另一套授权。引用/依赖、关闭资格、准确来源、同卷外部根、恢复材料与操作锁是归档门，不因Unknown而放宽。默认占用检查需要lsof，搜索验证需要rg。缺失/失败时报告受阻，不自行安装。目录FD与占用采样不能保证没有非协作并发写者。

## 安全清理前置

先读取明确cleanup-profile：[通用](../examples/cleanup-profile.example.json)、[文档](../examples/cleanup-document-profile.example.json)、[Unity](../examples/cleanup-unity-profile.example.json)。准确request示例见[请求](../examples/cleanup-request.example.json)。

```bash
./bin/fifan-maintain cleanup inspect --project /absolute/path/to/project --profile /outside/cleanup-profile.json
./bin/fifan-maintain maintenance workflow --project /absolute/path/to/project --profile /outside/cleanup-profile.json --records-dir /outside/records
```

maintenance workflow默认inspect，已声明的quarantine/purge模式仍须准确对象、计划指纹及所需授权。tools/run_project_maintenance.py是同一入口的薄封装。先明确可丢弃的旧构建/已闭日志，再隔离并核验；永久删除仅处理本工具自有隔离载荷，需要单独批准，且不可恢复。清理后重建保留材料基线，再执行声明的后续动作。依赖环境、正式素材、未知来源或历史年龄本身不会自动取得删除资格。

## Agent与Skill

CLI可由具有本地命令执行能力的Agent或人直接使用，不绑定模型。skill/SKILL.md按Codex工作流提供指引；部署前配置工具实际入口，检查已有Skill来源并保护未知编辑。Skill不是CLI安装器，不自动安装依赖、启用Hook/定时任务或修改目标项目。可选Fifan只读角色需要宿主真实隔离入口，缺失时不能用宽权限角色冒充。

## 命令合同与状态

用./bin/fifan-maintain --help及各子命令--help查看当前准确参数。schemas/保存37份合同定义，examples/提供普通、文档与Unity的合成输入；坏/未关闭示例用于拒绝行为，不能自动修成产品数据。

Passed表示明确范围内实际通过；Failed表示已检查并发现失败；Blocked表示所需前提不满足；Unknown表示覆盖/语义或证据不足；Not run表示没有运行。各域分别解释，不用单个全局标签掩盖缺口。

[验证和平台限制](VALIDATION.md) · [开发测试](TESTING.md) · [依赖与声明](DEPENDENCIES.md)
