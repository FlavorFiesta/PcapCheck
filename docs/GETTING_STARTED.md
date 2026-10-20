# 开发与构建

支持平台：Windows 10/11。桌面与后端以 Python 3.12 验证；网页端使用 Node.js 22。

## 桌面端

安装 [Wireshark](https://www.wireshark.org/download.html)，保留 TShark 组件；实时抓包另需自行安装 Npcap。PowerShell 中执行：

```powershell
python -m venv backend/.venv
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.txt
./start_desktop.bat
```

设置中确认 `tshark.exe` 路径。源码运行数据保存在 `backend/data/`，程序首次启动自动创建；不要提交该目录。

## 网页端

```powershell
cd frontend
npm ci
npm run build
cd ..
./start.bat
```

访问 `http://127.0.0.1:8123`。开发时先启动后端，再在另一个终端执行 `cd frontend; npm run dev`，访问 `http://127.0.0.1:5173`。API 文档为 `http://127.0.0.1:8123/docs`。

应用没有公网访问的登录验证。默认本机启动地址为 `127.0.0.1`，不要把监听地址改为 `0.0.0.0` 用于直接公开部署。

## Windows 打包

安装 Inno Setup 6 后执行：

```powershell
backend/.venv/Scripts/python.exe -m pip install -r backend/requirements-build.txt
./packaging/build_windows.ps1
```

默认生成不捆绑 TShark 的中文安装版和免安装版，使用者单独安装 Wireshark。脚本拒绝覆盖已存在的同版本输出目录；重打包前先将旧输出移到仓库外的备份目录。

如果维护者有意分发捆绑 TShark 的版本，可使用 `-BundleTshark`。先完成 [发布要求](RELEASING.md) 中对应版本的源码与第三方许可材料，勿将本机整个 Wireshark 目录直接视为可公开分发的完整成品。

## 源码导出

```powershell
python tools/export_public_source.py --output opensource/PcapCheck
```

导出工具采用允许清单，只复制代码、公开文档和构建配置，不复制运行数据、内部记录、外部样本、依赖目录或 Git 历史。目标目录必须不存在。导出后在目标目录初始化 Git，再执行 `python tools/check_public_source.py`。导出检查用于发现常见问题，发布前仍应人工查看待提交文件。
