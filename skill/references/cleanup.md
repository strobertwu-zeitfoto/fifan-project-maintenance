# 显式安全清理

仅在用户明确要求识别或清理可丢弃旧构建、已关闭任务的纯过程日志、一次性输出时读取。与文档整理和 directory 归档分开；默认 inspect，不因 profile 写了外部根就访问它，更不默认隔离或永久删除。普通几份 MD 沿原流程，不自动全盘。

## 先判保留价值，再做清理预检

确认真实工程根、规则、当前授权及本轮准确范围。新 cleanup-profile 与 request 使用独立合同，不把旧 task-profile、directory-profile 或 v2 文件请求当清理许可。先核对实际安装入口与 help，命令和已验证输入见工程 [USAGE](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/blob/main/docs/USAGE.md) 的 1.4 节；缺能力保留原错误，不用临时 shell 删除补齐。

机械 inspect 先给保留 R、待清理 D、未决 U 及覆盖缺口。名称、年龄、体积、重复、新包存在和没找到引用都只是线索，D 也不是删除授权。Agent 必须核实来源、用途、关闭依据、准确保留对象、唯一失败／验收证据和可接受损失。含 WIP 的旧包被批准丢弃也不等于可重建；明确记录失去原样复现能力。

正式代码、资源与 .meta、正式数据／存档、凭据、版本库、用户保护项、current 原件及必要记录根保留；Unity 的 Assets、Packages、ProjectSettings 和首版不支持的 Library／Temp、依赖环境、系统缓存不进入本批清理。current 原件无自引用也受保护，不能删声明、缩小消费者范围或删除阻塞文件来关闭 Unknown。

仅同一已批准 D 集合中的材料，才可能不再作为未来保留消费者全文扫描其他 D 对象；仍要核实它不属于 R/current，以及保留资料是否依赖它。未批对象、另一批对象或处置未完成的成员不自动共享豁免。保留的大日志继续受控流式读取；动态消费者逐项绑定核实，未知和外部限制如实保留，不能推断全世界无依赖。

## 精确批准、隔离与不可逆 purge

先预览准确对象、关闭／损失依据、保留记录、引用覆盖、完整 SHA／清单、占用及三根身份。扫描权限不授予正文、移动或删除权限；完整指纹用于绑定材料，不是用户批准凭证。用户可以一次批准准确批次的隔离加永久删除；已有覆盖的授权连续执行，不逐文件重问。只有隔离许可时保留可恢复状态，不自动 purge。

quarantine 只做同卷无覆盖移动到外部自有隔离空间；purge 只删除本工具已完整隔离、当前清单与依据仍匹配且准确获批的载荷。运行时明确匹配 quarantine-root 和 records-dir，三根互不包含；计划内路径不自授权限。隔离区不等于历史归档区，不清任意原工程路径、1.3 归档、记录根或隔离根本身。不使用 rm -rf、find -delete、git clean、系统废纸篓或跨卷复制后删除。

拒绝父子重叠、别名、链接、特殊文件、共享硬链接、目标占用和状态漂移。完整私有计划／journal 为 0600，操作目录 0700，保留原始恢复数据；stdout 只看限额脱敏摘要，不把完整清单、备份或日志正文发送模型。暂停非协作外部写者，占用采样和协作锁不等于绝对无并发保证。

新类别首次使用小批实际隔离、核验、恢复、核验，再重新预览隔离；相同代码和条件的有效演练可复用，不为每次 purge 重复整链。恢复不得覆盖原路径新内容。purge 不可恢复，journal 不含可重建 payload；部分永久删除不能称整批可恢复。中断先保留现场与 intent，按同次记录观察协调；续 purge 仍须原许可和当前状态匹配，不盲目重发旧计划。

实际入口为 `cleanup inspect/preview/apply/verify/restore-preview/restore/purge-preview/purge/recover/history`，共用 `--project` 和 `--cleanup-profile`；动作写入用匹配计划的 `--approve-plan`，恢复 purge 方向用 `--approve-purge`。固定脚本 `tools/run_project_maintenance.py` 调用 `maintenance workflow`，默认 `--mode inspect`；明确 `quarantine` 或 `purge` 时重复传入准确请求、隔离计划及其批准指纹。不要把 stdout 摘要当完整 plan；完整私有材料保存在明确的工程外 `--plan` 与 REC。

purge 计划落盘不等于已删除：若全部原件仍完整、无 removed／意图后缺失、无源冲突，可重新做 restore-preview 并批准其新恢复计划，由工具取消尚未造成损失的 purge 方向，保留 cancelled_purge 指纹审计。已有任何实际损失时不能走这条完整恢复路径；旧 purge 计划取消后不能继续使用。

## 重建基线与分阶段交付

固定顺序为 inspect → 已批准 cleanup → rebaseline → 已声明 after-action → report。清理后重新取得保留来源、SHA、引用和实际目录状态；旧游标、影响证明与比较基线不能直接复用。原报告／快照不改，缺失由独立 sidecar 解释，不把 Missing 改 Passed。后续目录搜索／归档或少量 MD 检查、精确改写仍须各自授权和请求；脚本不产生语义批准或业务改写。

分别报告工程内减少、隔离增加、永久删除载荷逻辑字节、记录增长、保留正文变化和搜索可见性。移动不算磁盘释放；非原子观测、最终回执后新增、物理空间归因与模型用量的未知项必须明示。inspect 正文 0、候选完整哈希读取、保留引用读取和模型收到的输出量分开，不宣称清理全程正文 IO 为 0。

history 仅表示记录声明，不据 journal 自授隔离区读取；实际 verify 需显式根授权。旧 session 不处理 cleanup 新格式。局部 Passed 不替代全项目验收；真实业务清理、Unity／业务脚本、其他平台及用户接受未运行就保留 Not run。机械 CLI 不调用模型；复杂用途或不可逆边界按[现有分派规则](delegation.md)处理，不新增固定管理层或改变全局模型。

1.4.1的inspect规则提示位于`rule_hints`，仅显示有界匹配线索；提示截断或扫描不足为Unknown，命中仍不自动取得D资格。after-file已提交move后用同receipt续跑，核原授权/计划和真实后状态；部分旧file-plan不把recover回退当成前向重试，跨profile/config严格绑定保持。
