# 文档治理与归档

用于已授权的整理、移动、摘要和引用修复。只读检查无需加载本流程。

## 决定保留什么

先定位项目导航、正式决定、唯一计划与相关原件，区分当前合同、历史状态和未经确认的建议。保留独有决定、原任务、未决问题、失败、限制、验收边界和来源；历史进度数字不同不自动构成冲突。摘要不能覆盖原件，也不能把 implemented 改成 accepted。

一个事实保留一个权威落点。当前摘要只链接必要历史；计划保留任务及真实状态，决策记录保留适用范围和来源。沿用现有布局，不另建竞争台账。体量、重复、陈旧、未发现引用都只提供调查线索，不自动构成删除许可。

## 目标、归档与分域结论

先核对已授权记录，区别检查、实际改写、实际正文减量和语义接受；未应用 preview、单独 snapshot 或旧记录无 goal 都不证明瘦身完成。既有归档先做只读逐字覆盖证明，不制造同文 replace/plan；Exact 只代表明确选区原字节相同，不代表旧要求已经失效。不同、缺失、歧义与未查部分保留，不能自动移出独有内容。

将活动文件全字节、current 视图、归档、恢复材料分别核算，Unknown 不当零。storage 前后必须同完整角色/root/path 集合；未来快照/恢复记录要在 before 采集前精确列出并显式 allow_absent，只有已授权 FD 确认不存在才计零，普通缺件或事后猜测不升级为零。局部本地目标存在性完整、锚点不足、外链未查可同时成立；每域按自己的范围和缺口下结论，global Unknown 不改成 Passed。未知语法可能包含未解析本地引用时，相关域也必须 Unknown。

## 生成可审查请求

1. 先以准确 sources 做 preflight，再看 summary 和 read outline，按 heading/view 限额读必要正文。每批最多 10 文件、约 30 KiB；超限用绑定源指纹的游标拆批，并保留跨批引用与前置决定，不把未发送内容写成已读。
2. 多文件批次先从父profile派生准确sources，核对独立reference_bodies和历史预算；不因盘点可机械执行而递归所有evidence。对照授权范围生成项目外 JSON 请求。`replace` 含 `type,path,old,new`，`move` 含 `type,path,destination`。路径使用工程内规范相对路径；`old` 非空且必须唯一匹配（包括重叠匹配，如 aaa 中 aa 有两处），目标移动路径必须不存在。
3. 同文件多处修改用v3 replace_many，所有patch定位同一原始SHA，拒绝重叠/重复；编译为一次规范v2 replace，保留未改字节。无改动patch只记NoChange，全无改动不建plan，不继续用旧同名plan。v1 同批路径完全不重叠；v2 可先 snapshot 读取原件、再 replace 写同一源，其他写集合不重叠。同一文件多处替换可用一次覆盖这些修改的唯一连续原文块；若无法做到，拆成顺序批次，每次重新预览。移动后的正文修改也应另批执行。
4. 使用 `preview` 生成工程外 plan，核对原文、目标、指纹绑定及实际 diff。工具不校验用户授权，预览成功也不证明语义正确。
5. 先用相同范围的 before 报告与 plan 执行 compare，审查候选 overlay 和显式保留 guards；overlay 不是磁盘存在。再在有效授权内 `apply`，保留其返回的 journal 路径。跨文件逐项落盘，失败不撤销其他工作、不丢操作记录。
6. 使用 journal 执行 `verify`，再重新同范围 check 并 compare before/after；若归档跨目录，核对移动文档内部相对链接及所有入链。工具只会报告断链，不会自动修复。生成下一批精确 `replace` 请求，循环至必要引用有效，保留未知宿主锚点等未验证项。

归档需用 v2 snapshot 纳入 journal：明确源 path、destination、expected_sha256 和 origin（reference_base/classification_basis），先验证原件副本再改源，目的不覆盖。保留 guards 支持 snippet、完整 heading/table、唯一 anchor；明确的局部 exceptions 逐项核实，不豁免整块。示例与准确参数见工程 [使用说明](https://github.com/strobertwu-zeitfoto/fifan-project-maintenance/blob/main/docs/USAGE.md)。

比较按规范目标/锚点等稳定身份计多重引用，不以行号判断新增。来源、版本、视图或预算不匹配和覆盖不足时，不宣布没有新问题。当前/历史 view 必须先核实再声明精确行范围；details、目录名和标题本身不使旧要求失效。

执行 `apply`/`recover` 前暂停非协作外部编辑者。本工具用目录文件描述符上的跨进程锁协调自身操作，不能锁住其他编辑器，也不能绝对消除系统调用间的覆盖风险。禁止通过本批请求修改或移动 `.fifan-maintenance.json`；配置迁移另行设计。

不靠 Token 行号定位自动改写；它只是解析块提示。保留未修改字节与换行。此文件治理 CLI 不支持删除；独立 cleanup 的隔离／purge 必须另按[安全清理](cleanup.md)核对准确对象和已有许可，不能由普通整理授权推导。正式数据、发布或 Git 操作仍遵用户边界，没有覆盖则停在相应边界，独立工作继续。

## 中断与恢复

`apply` 输出 journal 指向工程外恢复目录。失败时先保留该目录和原错误，再检查文件现状；不要重新运行同一 plan 冒充恢复。`recover --journal <原记录>` 只恢复本工具可确认的操作，核对指纹、路径与目录归属；检测到后续修改会停止；执行期间仍须暂停外部编辑，不能据此承诺绝对不会覆盖并发新工作。恢复后再运行 `verify` 与引用检查。

操作记录含备份原文，不上传模型或公共仓库。v2 逆序恢复正文，并只处理本工具创建且内容/归属未变的快照副本；已有或后改的历史不得删除。v1 请求和 journal 继续支持，真实根或配置变化仍拒绝，缺新证据不猜补。恢复只处理自身已记录产物，不接管其他临时文件，也不承诺断电等所有故障下的全批事务恢复。

## 交付边界

区分代码/格式、集成、实际宿主、真机及人工体验证据。Unknown、Not run、Blocked 不写成 Passed；报告或候选自报通过不等于验收。检查没发现问题仅代表已报告覆盖范围。保留唯一计划原有接受门，由 Root 或明确受托 PM 核实当前候选后推进；用户体验仍由用户接受。


## 多批终态与恢复

用明确授权的 history 查询已有报告/plan/journal，未应用preview、单独snapshot和缺goal的旧记录不算瘦身完成。会话只引用真实root与明确执行顺序journal、路径/指纹，不建竞争进度库；标准profile使用带root的引用包装，不把其源码加未支持字段。

session report区分单记录即时约束与后批合法替代，不把旧verify Failed改成Passed。恢复先只读recovery-preview验证链、终态、源/归档SHA与inode归属，再持锁按计划逆序recover；链断裂、分叉、歧义、后改或归属变化停止。中断后保留真实完成步骤和旧journal，重新preview，只续未完成部分；钉住journal原始SHA的引用须在内容变化后重新核实。

使用archive proof时保留原v3请求，权威执行产物为prepare_request返回的sealed v2 plan；不要单独重预览其规范request来代替双方完整指纹的写前条件。外部根proof只读可Exact，但当前不能编译成跨根v2持久guards。

1.4.1对旧文件批次也保守拒绝名称等价/同实体的不同路径，合法snapshot→replace保持支持。session终态漂移不得按可恢复性宣告all_applied；同文replace不算实际改写。局部分页不解析整篇标题，outline/heading解析受协作时间预算约束。
