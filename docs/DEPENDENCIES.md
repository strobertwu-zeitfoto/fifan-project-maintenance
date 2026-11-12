# 依赖与第三方来源 / Dependencies and notices

运行依赖固定于pyproject.toml和requirements.txt；运行时没有模型SDK或网络客户端。安装依赖可能需要网络，实际项目检查离线。

| Component | Version | Role | Notice |
| --- | --- | --- | --- |
| markdown-it-py | 3.0.0 | CommonMark parsing | [MIT/upstream notice](licenses/markdown-it-py.txt), [additional notice](licenses/markdown-it-py-1.txt) |
| mdurl | 0.1.2 | URL parsing | [MIT](licenses/mdurl.txt) |
| PyYAML | 6.0.3 | Safe, bounded YAML parsing | [MIT](licenses/PyYAML.txt) |
| tomli | 2.2.1 | Python3.9/3.10 TOML compatibility | [MIT](licenses/tomli.txt) |
| pytest | 8.4.2 | Development tests only | Installed package's upstream notice |

No runtime dependency source is vendored. Public parsing APIs are used; project plugins are not loaded. Eleven applicable parser tests referenced markdown-it-py3.0.0 upstream tests; associated notices remain included. A historical review of another parser version is not evidence for the pinned runtime version.

搜索验证需要rg，默认占用检查需要lsof。缺失、失败或覆盖不足不会自动变成通过，也不自动安装工具。部分安全原语是macOS专用，其他系统不由Python版本声明推定可用。

Development schema validators additionally use jsonschema and referencing, outside the core runtime dependencies. Their historical artifact collections are not included in the public snapshot; ordinary installation and unit tests do not require those historical collections.

The project's own license remains unselected: [NOTICE](../NOTICE.md).
