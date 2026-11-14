# 1.5 工作入口

这些入口仍需准确项目、范围、预算和既有授权；不替代语义接受或原生操作检查。

## 读取预算和续办

目录和 cleanup profile 可显式增加 `reference_batching`，累计上限与原单批上限分开。先运行 `directory reference-estimate` 或 `cleanup reference-estimate` 核对本批所需 IO，再通过 `reference-advance` 分批取得检查回执；Partial 不是完整覆盖。续办使用原请求、`--resume` 和另行保留的 `--reference-fingerprint`。输入、范围、实现或原件漂移拒绝旧回执。修改入口重新完整分批读核，外部回执不能自授隔离/删除资格。没有 opt-in 时旧预算含义不变。

## 动态提示

`reference-review --project ROOT --request REPORT [--files EXACT_FILES...]` 对已观察到的来源去重；显式 `--files` 可按原件 SHA 验证并补充分层提示。复核包不是安全批准。普通动态语法、路径构造、文件访问能力和已确认依赖分别理解；固定输出文件名、无字面命中均不能证明没有依赖。明确静态的单行 Python f-string 沿原字面路径规则检查；其他插值、嵌套访问和不明确合并路径继续 Unknown。不要为了得到 Passed 自动删减当前消费者声明。

## 联合预演

`joint-preview --project ROOT --profile PROFILE --file-plan FILE_PLAN --request ARCHIVE_REQUEST --archive-root ARCHIVE --records-dir RECORDS` 只投影准确文件候选和目录移动后的导航。显式新引用文件尚不支持时保持 Unknown。成功投影不是可执行归档计划：真实应用文件候选后，还须 fresh 原生归档预览，再执行和验证。恢复先归档目录、后文件变更；中断沿已有记录，不盲目重放。

## 明确生成物清理

缺历史编译信息的已批准旧生成物可使用准确 profile candidate 的 `disposal_policy=generated_artifact` 与请求 `generated_disposal` 双重声明；还须明确接受损失且无独有证据。缺失 build 信息在报告保持 Unknown，不能伪造。默认 old_build 合同不变；生成物声明不是删除授权，隔离/恢复/purge 继续原生检查与准确计划批准。详见工具 `docs/GENERATED_BUILD_DISPOSAL.md`；不要用改分类、缩范围或自造 metadata 绕过保护。

## 文档保留、绑定与收益

`advisory --project ROOT --request REQUEST [--output NEW_EXTERNAL_REPORT]` 检查明确的原文/候选 SHA 与逐条字面保留要求，可定位任务编号、数值、否定及待验句子的缺失。所声明绑定文件对原文的 hash 引用仅提示影响，不重建清单或生成加载凭证。显式搜索文件集合的变化不等于实际编辑器行为；没有减少时优先 NoChange。语义保留仍须人或独立审查核实，不能只靠相同标题、链接、原件备份或较小字节数宣告无遗漏。

细节及硬上限见工具仓库 `docs/REFERENCE_BATCHES.md`、`docs/UPGRADE_1_5.md` 和相应 schema/example。按工具真实版本调用；缺命令时报告，不用另写宽权限脚本绕过。
