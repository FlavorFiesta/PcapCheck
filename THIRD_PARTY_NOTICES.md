# 第三方组件与分发说明

MIT 许可证覆盖本项目自行创建的代码和文档，不替代第三方软件的许可证。依赖清单及精确前端版本分别位于 `backend/requirements.txt` 与 `frontend/package-lock.json`；安装依赖和发布二进制时保留相应版权及许可文件。

## 主要组件

| 组件 | 用途 | 上游许可 / 来源 |
| --- | --- | --- |
| Python、Tk/Tcl | 后端与桌面运行时 | PSF / Tcl/Tk 各自许可，保留运行时许可文件 |
| FastAPI、Uvicorn、Pydantic、python-multipart、tkinterdnd2 | API、数据模型、上传与拖放 | 各自上游发行包附带的许可，发布前以精确安装版本为准 |
| React、React DOM、React Router、Zustand、TanStack Virtual、marked | 网页界面 | 以锁文件对应发行包的许可为准 |
| Apache ECharts、echarts-for-react | 可视化 | Apache-2.0 / MIT；以精确发行包为准 |
| PyInstaller | 可执行文件构建 | 上游 GPL 及其 bootloader 分发例外；保留工具声明 |
| Inno Setup 与简体中文语言文件 | 安装器 | 保留来源与文件头；使用 [官方条款](https://jrsoftware.org/isinfo.php) 核对发布版本 |

这张表是组件索引，不是所有传递依赖的完整法律清单。首次公开二进制之前，应依据精确依赖版本生成完整第三方许可材料。

简体中文安装器翻译来自 [kira-96/Inno-Setup-Chinese-Simplified-Translation](https://github.com/kira-96/Inno-Setup-Chinese-Simplified-Translation)，版权声明与 MIT 全文保存在 `packaging/languages/LICENSE.txt`；原语言文件的来源说明保留不变。

## Wireshark / TShark

项目通过独立进程调用 TShark；干净源码仓库不包含 Wireshark 的二进制、源码或外部测试抓包。请用户从 [官网](https://www.wireshark.org/download.html) 单独安装。

如果后续 Release 捆绑 TShark / Wireshark，请针对实际分发版本保留 GPL 及各第三方许可，并按其要求提供对应源码，不能只附本项目的 MIT。资料：[Wireshark FAQ](https://www.wireshark.org/download/docs/faq)、[开发者指南](https://www.wireshark.org/docs/wsdg_html/)。

已有本地 1.0.7 安装包属于捆绑 Wireshark 的历史产物；本次源码开源准备没有将其重新制作为完整的第三方合规发布包。不要直接将其作为本次源码仓库的 Release 附件。

## Npcap

源码仓库和默认公开打包流程均不包含 Npcap 安装器。实时抓包用户自行从 [Npcap 官网](https://npcap.com/) 安装并遵守使用条款。不要在未核实授权的情况下随项目分发 Npcap，参见 [OEM 再分发许可](https://npcap.com/oem/redist)。

## 测试样本、截图与知识文章

外部下载抓包和真实网络抓包均未收入公开源码，文件可下载并不表示有权再分发。重新分发前核实具体素材的授权与隐私。公开仓库只提供自行生成合成样本的代码。

知识文章中对标准和协议的引用属于排障资料索引；被引用的标准、上游资料及第三方商标不因此变为 MIT 许可。
