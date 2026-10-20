# -*- coding: utf-8 -*-
"""路径常量:统一用 pathlib,全部 UTF-8。"""
import sys
from pathlib import Path

# 打包后 backend exe 与运行时资源位于同一目录;源码运行时仍使用项目 backend/。
if getattr(sys, "frozen", False):
    BACKEND_DIR = Path(sys.executable).resolve().parent
    # 便携版把后端放在 <安装目录>/backend/，资源和用户数据在上一级。
    PROJECT_ROOT = BACKEND_DIR.parent
else:
    BACKEND_DIR = Path(__file__).resolve().parent.parent
    PROJECT_ROOT = BACKEND_DIR.parent
# 运行时数据目录(数据库、设置、上传、实时临时文件)
DATA_DIR = PROJECT_ROOT / "data" if getattr(sys, "frozen", False) else BACKEND_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
# 默认知识库目录
DEFAULT_KB_DIR = PROJECT_ROOT / "docs" / "kb"
# 测试样本目录
TEST_CAPTURE_DIR = PROJECT_ROOT / "tests" / "captures"


def ensure_dirs() -> None:
    for d in (DATA_DIR, UPLOAD_DIR):
        d.mkdir(parents=True, exist_ok=True)
