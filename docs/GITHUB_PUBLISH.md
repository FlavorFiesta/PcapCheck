# 首次上传 GitHub

推荐仓库名：`PcapCheck`。

仓库描述：`报文检查：面向 Windows 的本地抓包分析与中文网络诊断工具，支持 PCAP、TShark、26 条规则和可选 AI 分析。`

建议 Topics：`pcap`、`network-analysis`、`packet-analysis`、`tshark`、`windows`、`python`、`react`、`network-diagnostics`。

## 使用干净源码目录

公开准备工具已生成单独的干净源码目录。后续所有命令在这个目录执行，不要把带有真实数据的日常工作目录整体上传。

如果目录尚未初始化：

```powershell
git init -b main
python tools/check_public_source.py
git add .
python tools/check_public_source.py
git diff --cached --stat
```

检查无误后创建首次提交：

```powershell
git commit -m "Prepare PcapCheck 1.0.7 for open source"
```

Git 若提示身份缺失，配置你自己的姓名和邮箱；可使用 GitHub 提供的 noreply 邮箱。不在文档中替你编造作者身份。

## 创建并连接仓库

在 GitHub 点击 New repository，名称填 `PcapCheck`。选择 Public 时源码即公开；因为本地已有文件，不勾选自动添加 README、许可证或 .gitignore。复制新仓库 HTTPS 地址，再执行下列命令，将中文占位值替换为真实仓库地址：

```powershell
git remote add origin https://github.com/你的用户名/PcapCheck.git
git push -u origin main
```

GitHub 登录或令牌由你在本机登录流程处理；不要把令牌写入 remote URL、脚本或聊天。

## 仓库设置

- 检查 Actions 的自动验证结果。
- 在 Security 设置中开启私密漏洞报告和可用的依赖 / 密钥提醒。
- 在 About 中填写上述描述与 Topics。
- 安装包通过 Releases 单独发布，先阅读 [发布说明](RELEASING.md)。

首次推送后检查仓库的 Actions 结果；安装包按发布说明上传到对应版本的 Release，避免把二进制文件提交进源码历史。
