---
name: fifan-project-maintenance
description: 使用本地离线工具治理项目文档、引用、配置、素材、证据与 Unity 元数据，以及显式目录体检、搜索视野、同卷归档和已授权旧产物清理；不代替产品代码深审或运行验收。
---

# Fifan 项目维护

先机械筛查，再围绕疑点阅读和治理；保留 1.1/1.2 文件治理命令与记录兼容，目录分支另用独立格式。工具不调用模型、不联网、不启动 Unity、不执行项目脚本。自动发现本 Skill 不等于授权写入、全项目盘点或访问其他项目。

## 先确定目标和已有治理证据

用户明确要目录体检、搜索视野治理或整目录归档时，按需读取 [目录治理](references/directory-governance.md)，使用独立 directory-profile 与记录合同；普通几份 MD 不自动进入目录流程。默认 inspect，仅同卷、NoDelete，新的外部根必须有本次 runtime 明确授权，不能由计划自授。

用户明确要处理可丢弃旧构建、已闭过程日志或一次性输出时，按需读取 [安全清理](references/cleanup.md)。独立 cleanup 分支先判保留价值，再对准确批准对象隔离；永久删除另需覆盖该批 purge 的授权，只处理本工具自有隔离载荷且不可恢复。旧文件／目录入口和默认 inspect 继续 NoDelete；普通 MD 不自动增加全盘扫描或清理。

先区分本轮要入口整理（navigation）、当前正文瘦身（body-slim）还是明示资料集合的存储减量（storage）。先用 `history --records-dir <已授权外部目录>` 查询已有报告/journal，优先选尚需治理的少量关键 MD，不递归其他目录猜记录位置。被扫描、被改写、正文变小、语义已核实和用户接受是五种不同事实。

body-slim 看完整活动文件的实际字节增减，单独列 current 视图、复用/新建归档和工程外 plan/journal；折叠、加导航或只减少视图输出不能当文件缩小。若要求每份都缩小，不能用总量下降掩盖部分增长；目标未达照实报告，不为达标删除独有要求或恢复材料。storage 前后绑定同一完整角色/路径集合；未来归档/记录只有明确 allow_absent 且安全确认缺失时才计零，不能事后补造零或移出记录来制造收益。

## 确认范围并检查

工具 1.5.0 的预算预估/分批续办、动态提示复核包、导航与归档联合预演、文档保留及绑定影响检查见 [1.5 工作入口](references/maintenance-1.5.md)，遇对应问题时按需读取。先列硬阻断及预计收益；没有新增收益时允许 NoChange。已有同候选、同条件的有效回执先复用，缺口或漂移才补核；Unknown 不自动关闭。

- 从用户指定真实工程根开始，确认真实路径、适用祖先/局部规则、项目导航、唯一计划及当前授权；不扫描共同父目录猜工程。准备写入时核对范围内 Git 状态并保护已有修改。
- 本机入口为 `<工具安装目录>/bin/fifan-maintain`，要求 Python 3.9+ 与已安装的固定依赖。先核对入口可用；缺失时报告原错误，不自行安装或改用户目录。
- 关键文档治理先 `check --project <根> --files <准确文件...> --preflight`，核对来源、保护及预算，再用相同范围 `--format summary`，已有完整报告用 `report --input <工程外报告>` 限额摘要；不要先跑无范围的全项目检查。无临时范围时仍保留旧版 `check` 默认用法。仅在全量机械盘点已获授权时用 `inventory`。默认结果写 stdout，项目不变。`--output`、`--state`、`preview --plan` 和 `apply --operations-dir` 必须放工程外；报告/状态虽脱敏仍需保护；恢复记录可能含路径、发现或原文，按工程材料保护，不上传原件。
- 日常 `check` 默认按命名跳过 `history`、`archive`、`archives`、`evidence`、`ArtCandidates` 目录及含 `_HISTORY_` 或以 `REPORT_` 开头的文件（不区分大小写），仅为扫描选择提示；显式配置 `include` 会覆盖这项默认跳过，`inventory` 仍盘点。只有 `historical_sources:[glob]` 明确声明的历史源断链才降为 Unknown，不能仅凭名称生成或免除当前修复任务。`asset_groups` 仅表示候选/正式等显式标签分布，不代表采用。
- 通过 `.fifan-maintenance.json` 选择关键文件、声明引用合同与预算。`include`/`exclude` 控制扫描选择，不是读取权限隔离：已声明引用可能读取工程根内其他目标；`exclude`、`protected` 与 `.env` 等保护路径也会阻止直接引用读取。所有引用仍须属于本轮授权，禁止把其他真实项目加入配置。
- 只读取有关发现及必要原件，每批最多 10 文件、约 30 KiB 正文。必要上下文超过预算时拆批，保留依赖、独有要求和失败信息，不截断后宣称完整检查。`inventory` 全量机械读取不等于让模型全读。

临时范围优先用工程外 `--task-profile`（schema1兼容；新目标/独立历史预算用schema2）：`sources` 是准确文件列表，`reference_bodies` 是准许读取引用目标正文的 glob，`historical_roots` 只盘点历史目录元数据，三者分开；CLI 重复声明矛盾时 Blocked。链接存在性可做元数据核实，锚点目标正文未授权时 Unknown，不自动拉入邻近文件。项目保护规则优先。用 `views` 明确声明当前/历史的含首尾行区间，先由 Agent 核实；目录名、details 或标题不能自动裁定历史。

多个批次用 `profile derive --from <父profile> --sources <准确子集>`，核对权限转移预览，不能扩父授权。历史盘点先指定相关子目录，再用 history_budget 的层级/每根/总数/时间限额；下限或未遍历部分仍 Unknown。

大文档先 `read --file <源> --outline --max-depth 2`，可用字面 `--heading-filter` 收敛标题；再选择实际返回的 `--section-id`、原始 `--lines`、`--heading` 或 `--view`，用 `--max-output-bytes` 限额阅读；未完成时按返回的 `next_cursor` 用相同源/选择续读。源变化拒绝旧游标。展示脱敏内容不能直接充当精确 replace.old；需要原文片段时可在 preview 请求使用 old_locator（源SHA及原始字节区间），由CLI受控展开，不打印原文；已存在的读取、比较或检查能力不要另写临时机械脚本代替。

复杂批量语义治理按需使用 [分派规则](references/delegation.md)；普通三份 MD 不强制分派，机械 CLI 不调用模型，不改全局模型设置。

命令、字段、退出码和覆盖矩阵见工程的 [使用说明](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/blob/main/docs/USAGE.md)。不要只凭退出码 0 判定健康：读取 findings、coverage、截断和 Unknown/Not run；状态数值及历史差异需要 Agent 核实含义。

## 已授权治理

修改、归档、移动或整理前，读取 [治理流程](references/governance.md)。Agent 负责核实事实、保留历史和生成精确请求；CLI 提供 v1 `replace`/`move`，以及 v2 `snapshot`、精确保留 guards 和 v3 `replace_many` 输入编译；v3 的执行 plan/journal 仍为 v2，旧 v1/v2 路径保留。

- 同文件多处修改优先 v3 replace_many，全部 patch 绑定同一原件 SHA，拒绝交叠/重复/多写者；一处失配该文件不写。`replace.old` 必须在原文唯一出现（重叠匹配也计数）；同一路径不能任意重复写；v1 所有路径不重叠，v2 允许 snapshot 先读取原件、replace 再写同一源，归档目标不得覆盖。
- 优先用 `archive-coverage` 只读核对已有归档的明确选区，Exact 不代表要求失效。依赖 proof 的写入要在原 v3 请求内绑定并重新核对双方完整 SHA；外部根 proof 当前不可持久化为 v2 apply 条件。
- 先 `preview --task-profile ... --receipt ...` 看编译、限额 diff 与预计目标；在已有授权内 `apply`，不逐文件重新索取许可。应用后用 `report --measure-request` 与明确 before/after 重验实际目标，活动文件、归档和恢复资料独立核算。预览不是授权凭证；范围变化、删除、正式数据、外部发布和 Git 收尾仍遵当前用户边界。
- profile 预览先验证 schema/授权/FD 元数据，再编译或展开 locator；operation 源必须在 sources，guard/proof 原件须在 sources/reference_bodies。NoChange 也不跳过预检，同文件重复物理读取逐次计入预算；不把临时预算写进旧计划配置。
- 先保存同范围 before 完整 JSON，用 `compare --before ... --plan ...` 核对预览 overlay 和保留断言；候选不是磁盘已存在。`apply` 后重新 check 并 `compare --before ... --after ...`，来源/版本/视图/预算不匹配或 coverage 不足时不得宣布无新增问题。`verify` 仅核对本工具的文件状态。移动后重新检查引用，由 Agent 补精确修复请求；CLI 不自动改写链接。再运行适用的检查及必要宿主验证。
- 多批用显式顺序 session 清单，`session report/verify` 解释终态和后批替代；恢复先 `session recovery-preview`，再用其完整且仍匹配的计划 `session recover`，中断重新预览续未完成部分，不改旧单记录语义、不按mtime猜顺序。
- `apply`/`recover` 使用目录文件描述符跨进程协作锁；执行期间仍须暂停非协作外部编辑者，系统调用间不能绝对防止覆盖。失败保留项目外操作记录；恢复核对后续修改，不能把多文件批次称作原子事务。禁止用本批操作修改或移动 `.fifan-maintenance.json`；配置迁移须另行设计。

分域报告只在自身范围完整时给 no_new；本地目标存在性、锚点、外链、文档提示、归档覆盖和历史元数据分开，未知语法传播相关域，global Unknown 不改写成 Passed。

不启用 lychee，不加载项目插件或可执行配置，不自动清理产物、提交、推送、建定时任务。报告实际修改、有效证据、覆盖不足和 Git 状态；机械 Passed、Git 状态检查或证据哈希匹配均不代替运行、视觉、真机或用户接受。
