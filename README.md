# 报文检查 · PcapCheck

面向 Windows 的本地抓包分析工具：导入报文，查看协议与会话，运行诊断规则并生成中文报告。

**当前版本：1.0.8 · Python 3.12 · React / TypeScript · MIT**

## 能做什么

- 拖放或点击导入 PCAP、PCAPNG、CAP，以及 `.pcap.gz`、`.pcapng.gz`。
- 通过 TShark 解码报文，查看字段树、TCP/UDP 会话和协议统计。
- 运行 26 条本地诊断规则，关联 35 篇中文知识文章。
- 识别重传、RST、DNS/DHCP 异常、TCP/DNS/DHCP 无响应、IPv6 邻居发现与路径 MTU、抓包截断，以及部分 SMB/SIP/HTTP/2 错误。
- 导出诊断报告、查看历史记录、实时抓包。
- 可选配置兼容 OpenAI Chat Completions 接口的 AI 服务，支持辅助说明与 AI 直达分析。

本地规则诊断不需要 AI 服务。AI 功能默认关闭；启用后会将报文摘要发送给你配置的服务，脱敏开关也请在使用前确认。服务地址、密钥及报告等保存在本机，不随源码提供。

## 快速开始

准备 Windows 10/11、Python 3.12（包含 Tk）和 [Wireshark / TShark](https://www.wireshark.org/download.html)。实时抓包另需自行安装 [Npcap](https://npcap.com/)。源码中不附带这两个程序。

在项目根目录的 PowerShell 执行：

```powershell
python -m venv backend/.venv
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.txt
./start_desktop.bat
```

首次启动后，在设置页确认 TShark 路径，然后将抓包文件拖入主页。无需填写 AI 密钥也能运行本地诊断。

网页端开发、测试和打包命令见 [开发指南](docs/GETTING_STARTED.md)、[测试说明](docs/TESTING.md) 和 [发布说明](docs/RELEASING.md)。

## 项目结构

```text
backend/app/       FastAPI、报文解析、规则与数据访问
backend/tests/     单元测试和集成测试
desktop_gui/      Tkinter 原生桌面界面
frontend/         React / TypeScript 网页界面
docs/kb/          中文诊断知识文章
packaging/        Windows 打包脚本与中文安装器配置
tools/            知识库验证、合成样本和源码公开检查
```

## 诊断边界

规则结果用于排查线索，需结合抓包位置、双向流量与设备日志确认；没有命中规则不表示网络一定正常。加密正文、单向抓包和抓包结束处的无响应均可能影响结论。知识文章包含 AI 起草内容并保留审核状态标记。

本应用是本机工具，没有面向公网部署的用户认证体系。启动脚本默认只监听 `127.0.0.1`。

## 版本更新

### 1.0.8（2026-10-20）

- 使用 MIT 许可，补充开发、测试、贡献、安全和发布文档。
- 增加公开源码允许清单导出、密钥检查及 GitHub Actions 验证。
- 启动脚本默认仅监听本机，公开打包默认由用户另行安装 TShark。
- 更新 ECharts、React Router 及间接依赖，处理本次 npm 审计告警。
- 重新生成中文安装版、免安装版及源码包，补充随包第三方许可清单。TShark 和 Npcap 需单独安装。

### 1.0.7

- 优化主页标题、品牌区、拖放导入框、文字层次和留白。
- 当前抓包与诊断操作、报告选择与进度状态分行展示。
- 导入区支持键盘 Enter / 空格，空状态文案随宽度换行。
- 修复项目改名后的打包工具启动路径。

### 1.0.6

- 显示名改为“报文检查”，项目名改为 PcapCheck，安装界面使用简体中文。
- 扩充到 26 条规则和 35 篇文章，补充无响应、IPv6、抓包质量及业务协议诊断。
- 修正 PMTU、DHCP、TCP 乱序、TLS 告警等文章中的不准确表述。
- 增加旧数据库名称迁移与旧知识库路径兼容。

### 1.0.5

- 抓包文件支持拖放或点击导入，修复诊断竞态、部分脱敏与稳定性问题。

## 参与和许可

欢迎提交 Issue 和 Pull Request，提交前请阅读 [贡献指南](CONTRIBUTING.md)。安全问题请参见 [安全说明](SECURITY.md)，勿在公开 Issue 中附带真实密钥或客户抓包。

项目自身代码与文档按 [MIT](LICENSE) 许可发布，第三方内容保留各自许可，详见 [第三方组件说明](THIRD_PARTY_NOTICES.md)。首次创建 GitHub 仓库见 [上传指南](docs/GITHUB_PUBLISH.md)。
