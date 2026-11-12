# Fifan 项目维护助手

<img src="docs/images/mascot.png" width="192" height="128" alt="戴红十字护士帽、标有AI的文件夹小护士" />

**为 Vibe Coding 做项目维护。大部分重复检查与机械整理操作，由自动化脚本完成。**

AI 少翻文件，把 token 留给开发。

简体中文 · [English](README.en.md) · [官网 www.fifanlabs.com](https://www.fifanlabs.com)

<details open>
<summary>大白话版：先看看能帮你什么</summary>

| 给项目做体检 | 给文档减减肥 | 脚本先做，AI再看 |
| --- | --- | --- |
| 找出失效链接和资料问题 | 当前说明变短，历史仍保留 | 批量检查，按需读取重点 |

<img src="docs/images/workflow-zh.png" width="900" height="600" alt="工作流程：你提出检查或瘦身需求；AI文件夹护士判断必要内容；机器人脚本批量检查、统计和处理；AI核对结果，保留历史和恢复记录。默认先检查，修改与删除按授权执行。" />

### 已有记录的效果

| 场景 | 结果 |
| --- | --- |
| 真实项目的一份MD说明 | **41.5 KB → 4.9 KB**，当前正文减少88.1% |
| 真实项目13份关键MD | **794.6 KB → 209.0 KB**，当前正文减少73.7% |
| 测试中的20,005份历史文件 | 机械盘点，**正文读取0字节** |

这些是2026年11月的真实协作案例和合成测试，历史原件另行保留，不代表固定token节省比例。[更多案例与统计口径](docs/CASE_STUDIES.md)

你可以这样提需求：

> 检查这个项目最重要的说明和计划，先列问题，不修改。旧文件先让脚本查，有疑点再让AI读相关内容，尽量少读、少输出。

机械检查不调用模型；AI发起操作、解释或改写仍消耗额度。程序业务bug还需要相应代码检查和运行测试。

</details>

<details>
<summary>技术版：功能、安装与支持范围</summary>

本地CLI提供文档/链接/配置/依赖/素材/证据等检查、限额读取、精确修改预览、操作日志、多批恢复、目录盘点、搜索范围治理、同卷归档和明确授权的清理。配套Skill负责引导Agent限定范围与解释结果。

### 安装

推荐Python3.12；进入本仓库目录后：

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install .
./bin/fifan-maintain --version
```

```bash
./bin/fifan-maintain check \
  --project /absolute/path/to/project \
  --files README.md \
  --preflight

./bin/fifan-maintain check \
  --project /absolute/path/to/project \
  --files README.md \
  --format summary
```

依赖安装可能需要网络；项目检查离线。CLI不执行被检查项目的脚本/插件，不启动Unity。归档/清理的占用检查需要lsof，搜索验证需要rg；缺少能力时报告受阻，不自行安装。

### Agent兼容性

**CLI不绑定模型，可供支持本地命令执行的Agent接入。** 配套Skill按Codex工作流配置，需填入实际安装入口；其他Agent软件尚未逐一验证，浏览器专用或不能运行本地命令的Agent不能直接调用。

### 平台与安全

- 最低兼容Python3.9，推荐并默认3.12；已验证Intel macOS的3.9.6、3.12.14、3.15.2。
- 部分受控操作使用macOS专用接口；不宣称Windows、Linux、Apple Silicon或自由线程Python已经通过验收。
- 默认检查不改目标。修改、归档与删除按明确范围和授权执行；永久删除不可恢复。
- 目录FD、文件指纹与协作锁保留；其他编辑者仍须暂停，不能保证阻止所有并发外部写入。
- 报告、计划和恢复材料按要求放在目标工程外，不上传项目原文或凭据。

</details>

## 文档

- [使用说明](docs/USAGE.md) · [Agent Skill](skill/SKILL.md)
- [验证与限制](docs/VALIDATION.md) · [开发测试](docs/TESTING.md)
- [依赖与第三方声明](docs/DEPENDENCIES.md) · [许可状态](NOTICE.md)

项目许可证尚未选定；第三方声明保留。官网：[www.fifanlabs.com](https://www.fifanlabs.com)。
