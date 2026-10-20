# 贡献指南

Issue 和 Pull Request 可使用中文。提交问题时请附应用版本、Windows 版本、TShark 版本、复现步骤、预期行为和实际结果。

不要上传 API 密钥、真实账号、企业抓包、报告数据库或包含客户信息的截图。优先用 `backend/tests/pcapcraft.py` 构造最小合成样本；合成文件由脚本生成，不提交二进制抓包。

## 开发验证

```powershell
backend/.venv/Scripts/python.exe -m pytest backend/tests -q
backend/.venv/Scripts/python.exe tools/review_checks.py
backend/.venv/Scripts/python.exe tools/verify_kb.py
python tools/check_public_source.py
cd frontend
npm ci
npm audit --audit-level=moderate
npm run build
npm run smoke
```

需要 TShark 的测试会在未安装时跳过；外部样本测试需显式开启，详见 [测试说明](docs/TESTING.md)。请说明实际运行的检查和跳过原因。

新增诊断规则时，提供正例、反例、证据帧和误报边界，并同步知识文章与知识库校验。避免把“抓包中未出现响应”直接写成设备故障的确定结论。

提交应聚焦一个问题。新代码、文档和自行创建的测试素材必须具备贡献权限；第三方代码保留来源和许可。项目不要求转让版权，你的贡献按项目 MIT 许可证发布。
