# -*- coding: utf-8 -*-
"""LLM 网关客户端(OpenAI 兼容协议)。

原则:
- settings.llm.enabled=false 或 base_url/model 未配置 -> 返回 None / 空串,不发起请求;
- 任何网络异常都吞掉并返回空串 —— 绝不阻塞、绝不影响报告生成;
- 规则报告中的 LLM 只对 findings 做中文复述;
- AI 直达模式允许模型直接阅读抓包摘要,但报告会明确标注为 AI 分析,不冒充规则结论。
"""
from __future__ import annotations

import json
import ipaddress
import logging
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

_TIMEOUT_SEC = 30

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?:%[\w.-]+)?")
_DOMAIN_RE = re.compile(
    r"(?<![\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|local|lan|internal)(?![\w-])",
    re.IGNORECASE,
)


def is_configured(settings: Dict[str, Any]) -> bool:
    llm = (settings or {}).get("llm") or {}
    return bool(llm.get("enabled") and llm.get("base_url") and llm.get("model"))


def mask_text(text: str, enabled: bool) -> str:
    """脱敏:IPv4/IPv6 -> <IP-1>,域名 -> <HOST-1>(发送云端前的兜底处理)。"""
    if not enabled or not text:
        return text
    seen: Dict[str, str] = {}

    def sub(pattern_tpl: str, m: re.Match) -> str:
        val = m.group(0)
        if val not in seen:
            seen[val] = pattern_tpl.format(n=len(seen) + 1)
        return seen[val]

    def ipv6(m: re.Match) -> str:
        try:
            ipaddress.IPv6Address(m.group(0))
        except ValueError:
            return m.group(0)
        return sub("<IP-{n}>", m)

    text = _IPV6_RE.sub(ipv6, text)
    text = _IPV4_RE.sub(lambda m: sub("<IP-{n}>", m), text)
    text = _DOMAIN_RE.sub(lambda m: sub("<HOST-{n}>", m), text)
    return text


def _chat(base_url: str, api_key: str, model: str, messages: List[Dict[str, str]]) -> Optional[str]:
    url = base_url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url += "/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}" if api_key else ""})
    with urllib.request.urlopen(req, timeout=_TIMEOUT_SEC) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    choices = data.get("choices") or []
    if not choices:
        return None
    msg = choices[0].get("message") or {}
    content = msg.get("content")
    return content if isinstance(content, str) else None


def generate_narrative(findings: List[Dict[str, Any]], summary: str,
                       settings: Dict[str, Any]) -> str:
    """对 findings 生成中文叙述。未配置/失败一律返回空串(绝不阻塞)。"""
    if not is_configured(settings) or not findings:
        return ""
    llm = settings["llm"]
    masking = bool((settings.get("masking") or {}).get("enabled", False))
    try:
        user = (
            "以下是网络抓包诊断规则引擎的输出结果,请用中文写一段 200 字以内的诊断叙述,"
            "复述这些结论、点出最关键的问题和优先处理项。不要新增任何规则之外的结论。\n\n"
            f"总体摘要:{summary}\n\n" + "\n".join(
                f"[{f.get('tier')}] {f.get('rule_id')} {f.get('title')};"
                f"证据帧:{(f.get('evidence_frames') or [])[:10]};统计:"
                f"{json.dumps(f.get('stats') or {}, ensure_ascii=False)}"
                for f in findings[:30]
            )
        )
        user = mask_text(user, masking)
        out = _chat(llm["base_url"], llm.get("api_key") or "", llm["model"],
                    [{"role": "system", "content": "你是网络故障分析助手,只复述给定结论,不下新判断。"},
                     {"role": "user", "content": user}])
        return (out or "").strip()
    except Exception as e:
        log.warning("LLM narrative 生成失败(忽略,不影响报告):%s", e)
        return ""


def generate_direct_analysis(capture: Dict[str, Any], frames: List[Dict[str, Any]],
                             settings: Dict[str, Any]) -> str:
    """直接根据抓包摘要生成 AI 分析,不运行本地规则和知识库匹配。

    为控制请求体大小,最多发送前 160 帧和最后 40 帧;每帧只保留诊断相关字段。
    发送前仍统一走 IP / 域名脱敏。
    """
    if not is_configured(settings):
        return ""
    llm = settings["llm"]
    masking = bool((settings.get("masking") or {}).get("enabled", False))
    try:
        selected = frames[:160]
        if len(frames) > 200:
            selected += frames[-40:]
        frame_lines = []
        for frame in selected:
            frame_lines.append(json.dumps({
                "no": frame.get("no"), "ts": frame.get("ts"),
                "src": frame.get("src"), "dst": frame.get("dst"),
                "sport": frame.get("sport"), "dport": frame.get("dport"),
                "proto": frame.get("proto"), "length": frame.get("length"),
                "info": frame.get("info"), "stream": frame.get("stream"),
                "analysis": frame.get("analysis") or [],
                "expert": frame.get("expert") or [],
            }, ensure_ascii=False, separators=(",", ":")))
        meta = {
            "name": capture.get("name"), "frame_count": capture.get("frame_count", len(frames)),
            "protocols": capture.get("protocols"),
        }
        user = (
            "请直接分析下面的网络抓包摘要,用中文输出 300 字以内的首页诊断结论。"
            "本次请求没有运行本地规则引擎,也没有匹配本地知识库;不要声称已经运行了它们。"
            "请按‘结论、证据帧、可能原因、建议动作’组织内容;把模型推测明确写成推测。"
            "如果信息不足,请明确说明需要补充什么,不要编造数据。\n\n"
            f"抓包元数据:{json.dumps(meta, ensure_ascii=False)}\n"
            f"帧摘要(共发送 {len(selected)}/{len(frames)} 帧):\n" + "\n".join(frame_lines)
        )
        user = mask_text(user, masking)
        out = _chat(
            llm["base_url"], llm.get("api_key") or "", llm["model"],
            [{"role": "system", "content": "你是网络抓包分析助手,只基于给出的抓包摘要分析,不得伪造证据。"},
             {"role": "user", "content": user}],
        )
        return (out or "").strip()
    except Exception as e:
        log.warning("LLM 直达分析失败(忽略):%s", e)
        return ""


def test_connection(settings: Dict[str, Any]) -> str:
    """向配置的 OpenAI 兼容网关发最小请求,返回模型原文;异常由调用方转成可读 HTTP 错误。"""
    if not is_configured(settings):
        raise ValueError("LLM 配置不完整:请启用并填写 Base URL、模型")
    cfg = settings["llm"]
    out = _chat(
        cfg["base_url"], cfg.get("api_key") or "", cfg["model"],
        [{"role": "system", "content": "你是连接测试助手。只回复：连接成功。"},
         {"role": "user", "content": "请回复连接成功。"}],
    )
    if not out:
        raise RuntimeError("模型返回为空")
    return out.strip()
