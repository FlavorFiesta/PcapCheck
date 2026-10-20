# 测试说明

## 常规测试

```powershell
backend/.venv/Scripts/python.exe -m pytest backend/tests -q -ra
backend/.venv/Scripts/python.exe tools/review_checks.py
backend/.venv/Scripts/python.exe tools/verify_kb.py
```

常规测试包含纯单元测试和使用自行合成报文的 TShark 集成测试。未安装 TShark 时，标记为 `tshark` 的测试会明确跳过。

GitHub Actions 运行不依赖 TShark 的单元测试、既有回归检查、知识库校验、源码公开检查、npm 审计、网页端构建及页面冒烟测试；它不代表已经验证真实抓包或 Windows 安装覆盖。

```powershell
backend/.venv/Scripts/python.exe -m pytest backend/tests -m "not tshark and not external_capture" -q
```

测试使用临时数据库和配置，避免读取或覆盖真实 API 密钥与抓包记录。

## 外部抓包回归

部分历史回归测试依赖 Wireshark 官方测试样本（`tests/captures/`）。公开源码不再分发这些文件。自行从 [Wireshark 官方源码的 test/captures](https://gitlab.com/wireshark/wireshark/-/tree/master/test/captures) 获取有权使用的样本，核实每份素材许可，然后执行：

```powershell
backend/.venv/Scripts/python.exe -m pytest backend/tests --external-captures -q -ra
```

未显式加参数时，`external_capture` 测试跳过；显式开启后缺少样本会失败，不将缺失样本当作成功。

## 合成数据

`backend/tests/pcapcraft.py` 是自行生成协议报文的工具，测试按需写入临时目录。生成可手动导入的演示抓包：

```powershell
New-Item -ItemType Directory -Force tests | Out-Null
backend/.venv/Scripts/python.exe tools/gen_synthetic.py
```

输出在 `tests/captures_synthetic/`，这些生成文件已被 Git 忽略。请勿使用真实客户抓包作为公开测试附件。
