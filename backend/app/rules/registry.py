# -*- coding: utf-8 -*-
"""规则注册表:每条规则一个模块,注册后由 analyze 管线统一执行。

LLM 不参与任何判断 —— 规则是结论的唯一来源。
"""
from __future__ import annotations

import logging
from typing import Callable, Dict, List

from .base import Finding, RuleContext, TIER_ORDER

log = logging.getLogger(__name__)

# rule_id -> 检查函数(返回 Finding 或 list[Finding])
_REGISTRY: Dict[str, Callable[[RuleContext], object]] = {}


def register(rule_id: str, needs_consumed: bool = False):
    """装饰器:把检查函数注册进 registry。

    needs_consumed=True 的兜底规则(如 U17)依赖其它规则的证据消费集合,
    会在全部普通规则跑完、ctx.consumed 填好后第二阶段执行。
    """
    def deco(fn: Callable[[RuleContext], object]):
        if rule_id in _REGISTRY:
            raise ValueError(f"规则重复注册:{rule_id}")
        _REGISTRY[rule_id] = fn
        fn.rule_id = rule_id
        fn.needs_consumed = needs_consumed
        return fn
    return deco


def all_rule_ids() -> List[str]:
    return sorted(_REGISTRY.keys())


def _run_one(fn, ctx: RuleContext, findings: List[Finding]) -> None:
    try:
        res = fn(ctx)
    except Exception:
        log.exception("规则 %s 执行异常", getattr(fn, "rule_id", fn))
        return
    if res is None:
        return
    items = res if isinstance(res, (list, tuple)) else [res]
    for f in items:
        if isinstance(f, Finding):
            findings.append(f)


def run_all(ctx: RuleContext) -> List[Finding]:
    """跑全部规则;单条规则异常不影响其它规则。

    两阶段:普通规则先跑;needs_consumed 兜底规则(如 U17)在
    ctx.consumed 填充后执行,保证其消费判定基于完整证据集。
    """
    findings: List[Finding] = []
    deferred: List[Callable[[RuleContext], object]] = []
    for rule_id in sorted(_REGISTRY.keys()):
        fn = _REGISTRY[rule_id]
        if getattr(fn, "needs_consumed", False):
            deferred.append(fn)
            continue
        _run_one(fn, ctx, findings)
    if deferred:
        ctx.consumed = {no for f in findings for no in f.evidence_frames}
        for fn in deferred:
            _run_one(fn, ctx, findings)
    findings.sort(key=lambda f: (TIER_ORDER.get(f.tier, 9), f.rule_id))
    return findings
