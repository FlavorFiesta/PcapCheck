报文检查（PcapCheck）免安装版 1.0.8

解压整个目录，再运行 PcapCheck.exe；保留 backend、docs 和 data 等配套目录。
默认公开打包流程不附带 TShark，使用前请自行安装官方 Wireshark（包含 TShark 组件）。
实时抓包还需要用户自行安装 Npcap。不要未经核实授权就随项目转发 Npcap 安装器。
AI 功能默认关闭，不附带 API 密钥。可在设置页配置；本地诊断无需启用 AI。
用户配置、数据库和报文记录保存在 data，升级与迁移时请先备份。

软件自身代码采用 MIT 许可，详见 LICENSE。第三方组件条款见 THIRD_PARTY_NOTICES.md。
更新内容和使用方法见 README.md，发布与打包说明见 docs/RELEASING.md。
