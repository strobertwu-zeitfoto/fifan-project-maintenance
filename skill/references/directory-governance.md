# 显式目录治理

仅用于用户明确授权的目录体检、搜索视野治理或目录归档。普通几份 MD 整理沿原流程，不自动追加全目录扫描；这是同一个 Skill 的按需分支。

## 先确认对象和默认阶段

从准确工程根确认规则、关键入口、当前/历史分类和本轮材料。目录 profile 使用独立 schema1，不是旧 task-profile1/2，也不改变旧 DEFAULT_CONFIG 或 v2 plan/journal 指纹。机械统计、哈希、搜索核对、清单校验均由 CLI 完成，model_calls=0 不代表 Agent 用量为零。

使用 inspect 返回的原生路径。case/Unicode 比较键只用于约束匹配，不是执行路径；非原生拼写可被 PATH_ALIAS 拒绝，不自动改字，也不因大小写等价扩大历史资格或正文授权。

默认 inspect：先看限额元数据、分类和影响，再决定是否准备搜索或归档候选。元数据读取权限不授予正文读取或移动权限；关闭决定、引用原件、证据 SHA 与明确分类需要 Agent 核实。年龄、名称、体量、完全重复或没查到引用都不自动构成归档资格。普通三份 MD 不强制派工；复杂材料按[现有规则](delegation.md)分派，不增加固定 PM 层或模型 SDK。

明确 current 的 reference_sources 本身也默认保留，不是只有“存在入链”才保护；即使该当前文件没有自引用，也不能连同候选移走。不能为放行归档而自动删掉当前来源声明或缩小既有授权/保护依据。

## 三种不同收益

- 搜索负担：实际默认 rg 搜索列表及关键路径是否仍可见；不能用数量变少代替正确性。
- 工程内负担：归档后原工程范围中的目录数、文件数和字节变化；归档副本另列。
- 存储收益：工程、归档和恢复记录的明确测量集合。仅同卷移动通常不减少总磁盘存储，不能把少扫文件或源目录移出当作磁盘释放。

## 搜索视野与 JSONC

只改项目 `.ignore` 的唯一受控块和明确的 `.vscode/settings.json` 项，不改 `.gitignore`、全局设置或 `files.exclude`。配置支持原本不存在时创建；已有 JSONC 的 BOM、注释、尾逗号、换行和无关值需要保留。重复键、冲突或不能无歧义保留时停止，不全量重写。

搜索排除不改变读取授权，也不使引用证据失效；仍按明确 reference_sources 和保护规则检查，不能因目录被默认搜索隐藏就宣布没有依赖。

预览不写工程，模拟不等于原生 rg 已验。apply 前取真实 baseline，写后核对默认搜索列表和每个 critical path；必要验证失败只在候选指纹和归属仍匹配时回退。已有配置恢复原始字节；新建文件/目录按真实归属处理，不覆盖用户后改。VS Code UI 未实际运行就记 Not run，不把配置生成当 UI Passed。

## 同卷归档、定位和恢复

归档根、记录根和工程根互不包含。执行时必须显式提供匹配的 runtime archive-root/records-dir；plan 自带的路径不授予外部写权限。仅同文件系统整目录移动；拒绝跨盘、链接、特殊文件、不可可靠核对的共享硬链接及活跃/正式/受保护材料，不执行复制后删除、压缩或删除用户文件。

先试一个已授权批次：preview、apply、verify、实际 restore、verify，再重新 preview 后归档。扩展仅限已经授权的候选，不自动把更大目录加入。完整私有 plan/journal/manifest 是 0600 恢复材料，不能脱敏后保存；stdout 只给限额安全摘要，不发送完整原文、配置备份或完整私有日志给模型。

ArchivedResolved 只表示原路径已通过记录定位到归档，不等于旧路径仍存在。旧脚本、固定路径调用或旧工具不理解新定位时先 restore，再用旧入口；不改业务脚本来伪装兼容。旧 v2 session 不处理新目录/search-config journal，明确 Unsupported，不能混入旧恢复链。

中断后先观察同次操作和当前状态，用明确根预演再 recover；未知副作用不盲目重发，不覆盖后改文件。此 directory 分支保持 NoDelete，恢复只处理自身有归属记录的配置和移动状态；独立 cleanup 的显式许可不能由归档授权推导。跨文件仍非原子，执行期间暂停非协作外部写者。

准确命令、schema、运行限制及实际证据见工程 [USAGE](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/blob/main/docs/USAGE.md) 的 1.3 节；正式脚本默认 inspect，不把验证驱动当业务入口。未运行平台、真实编辑器 UI、业务脚本及用户接受分别保留 Not run/Unknown。

公开报告放在归档载荷根之外，避开records中的`*.directory.json`和`workflow-*/`私有空间；普通records报告仍可用。搜索恢复中断可用原workflow的restore-resume继续，保留原根和记录，不另造操作。
