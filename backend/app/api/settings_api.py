# -*- coding: utf-8 -*-
"""settings / filter / kb 路由。"""
from __future__ import annotations

from typing import Optional
from copy import deepcopy

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from .. import kb, llm, tshark_service
from ..filterlang import FilterCompileError, compile_expr
from ..settings import load_settings, save_settings

router = APIRouter()


# ---------------------------------------------------------------- 设置
class SettingsBody(BaseModel):
    tshark_path: Optional[str] = None
    llm: Optional[dict] = None
    masking: Optional[dict] = None
    kb_dir: Optional[str] = None


@router.get("/settings")
def get_settings():
    return _public_settings(load_settings())


def _public_settings(settings):
    result = deepcopy(settings)
    config = result.setdefault("llm", {})
    config["api_key_configured"] = bool(config.get("api_key"))
    config["api_key"] = ""
    return result


def _preserve_key(config, current):
    config = dict(config)
    config.pop("api_key_configured", None)
    if not config.get("api_key"):
        config["api_key"] = (current.get("llm") or {}).get("api_key", "")
    return config


@router.put("/settings")
def put_settings(body: SettingsBody):
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    if "llm" in patch:
        patch["llm"] = _preserve_key(patch["llm"], load_settings())
    return _public_settings(save_settings(patch))


@router.post("/llm/test")
def test_llm(body: SettingsBody):
    """测试当前或本次表单中的 LLM 配置,不写入设置文件。"""
    current = load_settings()
    if body.llm is not None:
        current["llm"] = _preserve_key(body.llm, current)
    try:
        reply = llm.test_connection(current)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"LLM 连接失败:{e}")
    return {"ok": True, "reply": reply}


# ---------------------------------------------------------------- 过滤器编译
class CompileBody(BaseModel):
    expr: str


@router.post("/filter/compile")
def compile_filter(body: CompileBody):
    try:
        display = compile_expr(body.expr)
    except FilterCompileError as e:
        return {"error": str(e)}
    tshark = tshark_service.resolve_tshark()
    if tshark:
        ok, err = tshark_service.validate_display_filter(tshark, display)
        if not ok:
            return {"error": err, "tshark_filter": display}
    return {"tshark_filter": display}


# ---------------------------------------------------------------- 知识库
@router.get("/kb/articles")
def kb_articles(rule_id: Optional[str] = Query(None)):
    if rule_id:
        return {"articles": kb.articles_for_rule(rule_id)}
    return {"articles": kb.scan_articles()}


@router.get("/kb/articles/{article_id}")
def kb_article(article_id: str):
    """返回单篇知识库全文,供报告引用和知识库详情页打开。"""
    article = kb.article_by_id(article_id)
    if article is None:
        raise HTTPException(404, f"知识库文章不存在:{article_id}")
    return article
