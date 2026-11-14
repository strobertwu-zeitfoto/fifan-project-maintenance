# 1.5 使用与升级

本版本为三个治理案例中已证实的操作负担增加原生入口。保留旧 profile、命令和记录语义；新能力显式选择。完整实施及验证状态见 [唯一工程计划](ENGINEERING_PLAN.md)，版本变化见 [Changelog](CHANGELOG.md)。

## 预算预估与分批续办

详见 [Reference batches](REFERENCE_BATCHES.md)。对目录或 cleanup 声明 `reference_batching` 后，实际资格检查、预览和执行可在每批限制内读取完整引用集。没有 opt-in 时沿旧预算，不能把提高累计额度误写成放宽每文件或单批限制。

```sh
./bin/fifan-maintain cleanup reference-estimate --project /tmp/example/project --profile /tmp/example/profile.json --request /tmp/example/request.json
./bin/fifan-maintain cleanup reference-advance --project /tmp/example/project --profile /tmp/example/profile.json --request /tmp/example/request.json --max-batches 1 --output /tmp/example/checkpoint-1.json
```

输出同时保留 IO 估计、覆盖范围和实测阶段耗时。检查点需连同可信保留的 fingerprint 续办；实际写操作不接受检查点代替重新读核。

## 动态提示复核包

`reference-review --project ROOT --request FULL_REPORT --files EXACT_SOURCES... --output NEW_EXTERNAL_REPORT` 按文件 SHA、行、列和表达式 SHA 去重并保留涉及候选，显式提供原件时生成语法/路径构造/文件访问分层。它不升级 Unknown，不证明没有动态依赖。新报告是无写权限的复核材料，不能传作原生操作计划。

## 文件候选与目录联合预演

详见 [示例合同](../examples/joint-preview.example.json)。`joint-preview` 需要真实 file-plan、archive request 和明确 runtime archive/records 根。它校验原件、候选、声明引用及归档后目标，返回独立的投影结果，不生成可以绕过原生检查的归档计划。先实际应用文件候选，再重新原生归档预览/执行；中断按各自真实记录恢复。新增引用文件与无法覆盖的语法继续 Unknown。

## 缺历史信息的明确生成物

详见 [生成物处置合同](GENERATED_BUILD_DISPOSAL.md)。默认 old_build 的完整元数据和同组保留包要求不变。准确 profile candidate 的 `disposal_policy=generated_artifact` 和同一请求的 `generated_disposal` 为双重声明；还须 closure、明确损失批准、无独有证据。历史 build 字段缺失仍列为 Unknown，不编造可重建性。单独 inspect/profile 不授权隔离或 purge；current/keep/正式源目录/数据库/链接/占用/漂移和原生恢复门保持。

## 字面保留与绑定提示

`advisory --project ROOT --request EXTERNAL_REQUEST --output NEW_EXTERNAL_REPORT` 使用 [请求示例](../examples/maintenance-advisory-request.example.json)。所有原文/候选/明确绑定文件均为准确项目相对路径及实际 SHA；保留要求是带 ID、kind 的单行字面片段。它给出前后行定位、字节变化、明确绑定影响、已声明搜索集合变化和可观察的恢复文件入口。

该入口不推断全部需求、不判断语义等价、不重建运行凭证。`Passed` 仅适用于本次声明的字面条件；全局语义接受和物理磁盘释放仍为 Unknown/Not run。实际 rg、VS Code 以及真实项目运行需各自的证据。

## 验证与部署

开发使用固定 Python 3.12 依赖和临时样例，实际安装为非 editable wheel；切换前核对安装指纹，逐文件备份/替换，最后切换运行环境。旧环境和改动前文件保留用于回退，不将开发源码的成功等同安装版已经生效。仅本机安装；未授权远端发布。
