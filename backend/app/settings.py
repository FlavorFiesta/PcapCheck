# -*- coding: utf-8 -*-
"""设置读写:backend/data/settings.json。

结构(契约):
{
  "tshark_path": "C:/Program Files/Wireshark/tshark.exe",
  "llm": {"base_url": "", "api_key": "", "model": "", "enabled": false},
  "masking": {"enabled": false},
  "kb_dir": "<项目根>/docs/kb"
}
"""
from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path
from typing import Any, Dict

from .paths import DEFAULT_KB_DIR, PROJECT_ROOT, ensure_dirs

_LOCK = threading.RLock()  # 可重入:save_settings 内部会再调 load_settings
_SETTINGS_FILE = None  # 惰性初始化,依赖 paths

_COMMON_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def _file():
    global _SETTINGS_FILE
    if _SETTINGS_FILE is None:
        ensure_dirs()
        from .paths import DATA_DIR
        _SETTINGS_FILE = DATA_DIR / "settings.json"
    return _SETTINGS_FILE


def _detect_tshark() -> str:
    """按 常见安装路径 -> PATH 的顺序探测 tshark。"""
    import os
    bundled = PROJECT_ROOT / "tools" / "tshark" / "tshark.exe"
    if bundled.is_file():
        return str(bundled)
    for p in _COMMON_TSHARK_PATHS:
        if os.path.isfile(p):
            return p
    found = shutil.which("tshark")
    return found or ""


def defaults() -> Dict[str, Any]:
    return {
        "tshark_path": _detect_tshark(),
        "llm": {"base_url": "", "api_key": "", "model": "", "enabled": False},
        "masking": {"enabled": False},
        "kb_dir": str(DEFAULT_KB_DIR),
    }


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings() -> Dict[str, Any]:
    with _LOCK:
        data: Dict[str, Any] = {}
        try:
            if _file().exists():
                data = json.loads(_file().read_text(encoding="utf-8"))
        except Exception:
            data = {}
        merged = _deep_merge(defaults(), data)
        kb_value = merged.get("kb_dir")
        if isinstance(kb_value, str):
            kb_path = Path(kb_value)
            if (len(kb_path.parts) >= 3 and
                    tuple(part.casefold() for part in kb_path.parts[-3:]) ==
                    ("pcapdoctor", "docs", "kb") and not kb_path.is_dir()):
                merged["kb_dir"] = str(DEFAULT_KB_DIR)
        # tshark 路径为空或缺文件时自动重探
        import os
        if not merged.get("tshark_path") or not os.path.isfile(merged["tshark_path"]):
            merged["tshark_path"] = _detect_tshark()
        return merged


def save_settings(patch: Dict[str, Any]) -> Dict[str, Any]:
    """合并写入(浅层 key 覆盖,dict 递归合并)。"""
    with _LOCK:
        current: Dict[str, Any] = {}
        try:
            if _file().exists():
                current = json.loads(_file().read_text(encoding="utf-8"))
        except Exception:
            current = {}
        merged = _deep_merge(current, patch)
        _file().write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        return load_settings()
