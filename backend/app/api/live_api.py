# -*- coding: utf-8 -*-
"""实时抓包路由:interfaces / start / stop / status / export(转存分析)。"""
from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import tshark_service
from .. import db
from ..live import MANAGER
from ..settings import load_settings

router = APIRouter()


@router.get("/live/interfaces")
def live_interfaces():
    tshark = tshark_service.resolve_tshark(load_settings().get("tshark_path"))
    if not tshark:
        raise HTTPException(503, "未找到 tshark,请到设置里指定路径")
    try:
        interfaces = tshark_service.list_interfaces(tshark)
        return {"interfaces": interfaces,
                **tshark_service.interface_diagnostics(interfaces)}
    except Exception as e:
        raise HTTPException(500, f"枚举网卡失败:{e}")


class LiveStartBody(BaseModel):
    iface: str
    frame_limit: Optional[int] = None
    # Compatibility for older web clients; the native UI uses frame_limit.
    snaplen: Optional[int] = None


@router.post("/live/start")
def live_start(body: LiveStartBody):
    try:
        frame_limit = body.frame_limit if body.frame_limit is not None else body.snaplen
        info = MANAGER.start(body.iface, frame_limit,
                             tshark_path=load_settings().get("tshark_path"))
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return {"started": True, **info}


@router.post("/live/stop")
def live_stop():
    return MANAGER.stop()


@router.get("/live/status")
def live_status():
    return MANAGER.status(tshark_path=load_settings().get("tshark_path"))


class LiveExportBody(BaseModel):
    name: Optional[str] = None


def _wait_for_capture_ready(capture_id: str, timeout: float = 120.0) -> dict:
    """Wait for the asynchronous live-pcap import before running rules."""
    deadline = time.monotonic() + timeout
    while True:
        row = db.query_one("SELECT status,error FROM captures WHERE id=?", (capture_id,))
        if row is None:
            raise HTTPException(404, f"capture 不存在:{capture_id}")
        status = row["status"]
        if status == "ready":
            return {"status": status}
        if status == "error":
            detail = (row["error"] or "实时抓包导入失败")[:800]
            raise HTTPException(422, detail)
        if time.monotonic() >= deadline:
            raise HTTPException(504, "实时抓包导入超时，请稍后在历史记录中查看导入状态")
        time.sleep(0.2)


@router.post("/live/export")
def live_export(body: LiveExportBody):
    """把当前抓包缓冲(临时 pcap)转存为 capture,进入统一诊断管线。"""
    try:
        capture_id = MANAGER.export_buffer(body.name)
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    return {"capture_id": capture_id}


@router.post("/live/analyze")
def live_analyze(body: LiveExportBody):
    """前端"分析当前数据"一键入口:转存 buffer -> 走同一条诊断管线。"""
    # The web UI can invoke this while capture is still running.  Stop first so
    # tshark has flushed and closed the pcap before the async importer reads it.
    MANAGER.stop()
    try:
        capture_id = MANAGER.export_buffer(body.name)
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    from ..analysis import analyze_capture

    _wait_for_capture_ready(capture_id)
    report_id = analyze_capture(capture_id)
    return {"capture_id": capture_id, "report_id": report_id}
