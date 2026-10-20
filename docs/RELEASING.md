# 发布说明

源码和二进制分开发布：源码进入 Git 仓库，安装包放到 GitHub Releases，不提交 `packaging/output/`。

## 发布前

1. 同步 README 更新记录、桌面端版本、后端版本、前端 package / lock 版本、Inno Setup 与打包脚本版本。
2. 执行 [测试检查](TESTING.md)，记录通过及跳过的内容；检查安装器中文界面、升级数据保留和便携版启动。
3. 执行 `python tools/check_public_source.py`，人工检查 `git diff --cached` 与待提交文件列表。
4. 确认没有密钥、真实抓包、数据库、日志、内部文档、截图或外部样本。
5. 按精确依赖版本收集第三方许可材料，完成二进制分发核查后再上传。

## 生成安装包

```powershell
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements-build.txt
./packaging/build_windows.ps1
```

默认安装包不带 TShark / Wireshark / Npcap，用户另行安装。打包会复制项目 MIT、第三方说明，以及由 `packaging/collect_licenses.py` 收集的 Python 运行时和依赖许可到 `licenses/`。收集失败将终止打包；更换构建环境或新增本地二进制库时，需要额外核对实际捆绑组件。

可选 `-BundleTshark` 会从本机 Wireshark 安装目录复制运行时。分发该版本前，保存实际 TShark 版本、构建信息、对应源码、GPL 与全部附属组件许可，并按 GPL 要求提供对应源码。不能只附一个主页链接代替应履行的源码义务。没有核实授权时不要捆绑 Npcap 安装器。

1.0.8 是包含开源准备修改的新构建。历史 1.0.7 EXE/ZIP 不包含这些修改，不应代替本版安装包上传。

## GitHub Release

从通过 CI 的提交创建 `v版本号` 标签，填写功能变化、已验证环境、已知限制及是否含 TShark。上传安装版、便携 ZIP、SHA256 校验和以及所需第三方材料。在 Release 中写明 Npcap 需要用户自行安装。

```powershell
Get-FileHash packaging/output/*.zip, packaging/output/*.exe -Algorithm SHA256
```
