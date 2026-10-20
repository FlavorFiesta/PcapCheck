# -*- coding: utf-8 -*-
"""知识库:扫描 docs/kb 下的 Markdown 文章与 frontmatter。

frontmatter(--- 包围的 YAML 子集)支持字段:
  title, rule_ids, protocols, symptoms, severity
rule_ids 支持 `[R01, R02]` 或 `R01,R02` 两种写法。
目录不存在/无文章时返回空列表,不报错(RAG V1 兜底:按 rule_ids 匹配全文)。
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

_LIST_RE = re.compile(r"[\[\]]")


def _parse_value(raw: str):
    """frontmatter 值解析:[a, b] / 逗号分隔 -> 列表;true/false/整数 -> 对应类型;其余 -> 标量。"""
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        items = _LIST_RE.sub("", raw).split(",")
    elif raw in ("true", "false"):
        return raw == "true"
    elif re.fullmatch(r"\d+", raw):
        return int(raw)
    elif "," in raw:                       # rule_ids: R01,R02 写法
        items = raw.split(",")
    else:
        return raw.strip("'\"")
    return [x.strip().strip("'\"") for x in items if x.strip()]


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def parse_frontmatter(text: str) -> tuple:
    """返回 (meta dict, 正文)。无 frontmatter 时 meta 为空。"""
    meta: Dict[str, Any] = {}
    body = text
    if text.startswith("---"):
        parts = text.split("\n---", 2)
        # 严格一点的解析:第一行必须是 ---
        lines = text.splitlines()
        if lines and lines[0].strip() == "---":
            end = None
            for i in range(1, len(lines)):
                if lines[i].strip() == "---":
                    end = i
                    break
            if end is not None:
                for line in lines[1:end]:
                    if ":" not in line or line.strip().startswith("#"):
                        continue
                    key, _, val = line.partition(":")
                    meta[key.strip().lower()] = _parse_value(val)
                body = "\n".join(lines[end + 1:]).lstrip("\n")
    return meta, body


def scan_articles(kb_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """扫描目录下 *.md 的元数据(不读正文)。目录缺失返回 []。"""
    if not kb_dir:
        from . import settings as app_settings
        kb_dir = app_settings.load_settings().get("kb_dir")
    root = Path(kb_dir) if kb_dir else None
    if not root or not root.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    for p in sorted(root.glob("*.md")):
        try:
            meta, _ = parse_frontmatter(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        title = meta.get("title") or p.stem
        if isinstance(title, list):
            title = ", ".join(str(x) for x in title)
        out.append({
            "id": p.stem,
            "title": title,
            "rule_ids": _as_list(meta.get("rule_ids")),
            "protocols": _as_list(meta.get("protocols")),
            "symptoms": meta.get("symptoms") or "",
            "severity": meta.get("severity") or "",
            "file": str(p),
        })
    return out


def article_by_id(article_id: str, kb_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """按 id(文件名)取单篇,含正文。"""
    if not kb_dir:
        from . import settings as app_settings
        kb_dir = app_settings.load_settings().get("kb_dir")
    root = Path(kb_dir) if kb_dir else None
    if not root or not root.is_dir():
        return None
    p = root / f"{article_id}.md"
    # 防路径穿越
    if p.parent.resolve() != root.resolve() or not p.is_file():
        return None
    meta, body = parse_frontmatter(p.read_text(encoding="utf-8", errors="replace"))
    title = meta.get("title") or p.stem
    if isinstance(title, list):
        title = ", ".join(str(x) for x in title)
    return {
        "id": p.stem,
        "title": title,
        "rule_ids": _as_list(meta.get("rule_ids")),
        "protocols": _as_list(meta.get("protocols")),
        "symptoms": meta.get("symptoms") or "",
        "severity": meta.get("severity") or "",
        "file": str(p),
        "content": body,
    }


def articles_for_rule(rule_id: str, kb_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """按 rule_id 匹配文章(含全文)—— 诊断引用知识库的兜底实现。"""
    return _match_full(rule_id, kb_dir)


def _match_full(rule_id: str, kb_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    if not kb_dir:
        from . import settings as app_settings
        kb_dir = app_settings.load_settings().get("kb_dir")
    root = Path(kb_dir) if kb_dir else None
    if not root or not root.is_dir():
        return []
    out = []
    for meta in scan_articles(kb_dir):
        if rule_id in (meta.get("rule_ids") or []):
            full = article_by_id(meta["id"], kb_dir)
            if full:
                out.append(full)
    return out


def match_kb_ids(rule_ids: List[str], kb_dir: Optional[str] = None) -> List[str]:
    """对一组 rule_id 返回匹配的文章 id 列表(去重保序)。"""
    if not rule_ids:
        return []
    known = {a["id"] for a in scan_articles(kb_dir)}
    out: List[str] = []
    for rid in rule_ids:
        for a in scan_articles(kb_dir):
            if rid in (a.get("rule_ids") or []) and a["id"] not in out:
                out.append(a["id"])
    return [i for i in out if i in known]
