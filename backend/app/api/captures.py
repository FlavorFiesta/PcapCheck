# -*- coding: utf-8 -*-
"""captures 相关路由:导入/上传/列表/元信息/删除/帧/单帧详情/统计/Follow/分析。"""
from __future__ import annotations

import json
import os
from typing import List, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

from .. import analysis, db, imports, tshark_service
from ..filterlang import FilterCompileError, compile_expr

router = APIRouter()


# ---------------------------------------------------------------- 模型
class ImportBody(BaseModel):
    path: str


def _tshark_or_503() -> str:
    tshark = tshark_service.resolve_tshark()
    if not tshark:
        raise HTTPException(503, "未找到 tshark,请到设置里指定路径")
    return tshark


def _get_capture(capture_id: str):
    row = db.query_one("SELECT * FROM captures WHERE id=?", (capture_id,))
    if row is None:
        raise HTTPException(404, f"capture 不存在:{capture_id}")
    return db.row_to_dict(row)


def _public_meta(cap: dict) -> dict:
    try:
        protocols = json.loads(cap.get("protocols") or "[]")
    except json.JSONDecodeError:
        protocols = []
    return {
        "id": cap["id"], "name": cap["name"], "path": cap["path"],
        "size": cap["size"], "frame_count": cap["frame_count"],
        "first_ts": cap["first_ts"], "last_ts": cap["last_ts"],
        "protocols": protocols, "created_at": cap["created_at"],
        "status": cap["status"], "error": cap["error"],
    }


# ---------------------------------------------------------------- 导入/列表
@router.post("/captures/import")
def import_capture(body: ImportBody):
    path = os.path.abspath(body.path)
    if not os.path.isfile(path):
        raise HTTPException(400, f"文件不存在:{body.path}")
    _tshark_or_503()
    capture_id = imports.start_import(path)
    return {"capture_id": capture_id}


@router.post("/captures/upload")
async def upload_capture(file: UploadFile = File(...)):
    _tshark_or_503()
    data = await file.read()
    if not data:
        raise HTTPException(400, "上传内容为空")
    capture_id = imports.import_upload_sync(data, file.filename or "upload.pcap")
    return {"capture_id": capture_id}


@router.get("/captures")
def list_captures():
    rows = db.query("SELECT * FROM captures ORDER BY created_at DESC")
    return {"captures": [_public_meta(db.row_to_dict(r)) for r in rows]}


@router.get("/captures/{capture_id}")
def capture_meta(capture_id: str):
    return _public_meta(_get_capture(capture_id))


@router.delete("/captures/{capture_id}")
def delete_capture(capture_id: str):
    _get_capture(capture_id)
    db.execute("DELETE FROM frames WHERE capture_id=?", (capture_id,))
    db.execute("DELETE FROM reports WHERE capture_id=?", (capture_id,))
    db.execute("DELETE FROM captures WHERE id=?", (capture_id,))
    return {"deleted": capture_id}


# ---------------------------------------------------------------- 帧浏览
def _load_rows(capture_id: str, nos: Optional[List[int]] = None,
               offset: int = 0, limit: int = 100):
    base_sql = ("SELECT no,ts,src,dst,sport,dport,proto,length,info,stream,analysis,expert "
                "FROM frames WHERE capture_id=?")
    params: list = [capture_id]
    if nos is not None:
        if not nos:
            return []
        chunk = ",".join("?" * len(nos))
        base_sql += f" AND no IN ({chunk})"
        params += nos
    base_sql += " ORDER BY no LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = db.query(base_sql, params)
    out = []
    for r in rows:
        try:
            analysis_tags = json.loads(r["analysis"] or "[]")
        except json.JSONDecodeError:
            analysis_tags = []
        try:
            expert = json.loads(r["expert"] or "[]")
        except json.JSONDecodeError:
            expert = []
        out.append({
            "no": r["no"], "ts": r["ts"], "src": r["src"], "dst": r["dst"],
            "sport": r["sport"], "dport": r["dport"], "proto": r["proto"],
            "length": r["length"], "info": r["info"], "stream": r["stream"],
            "analysis": analysis_tags, "expert": expert,
        })
    return out


@router.get("/captures/{capture_id}/frames")
def list_frames(capture_id: str, offset: int = Query(0, ge=0),
                limit: int = Query(100, ge=1, le=20000),
                filter: Optional[str] = Query(None)):
    _get_capture(capture_id)
    nos = None
    if filter:
        try:
            display = compile_expr(filter)
        except FilterCompileError as e:
            raise HTTPException(400, f"过滤表达式错误:{e}")
        tshark = _tshark_or_503()
        cap = _get_capture(capture_id)
        ok, err = tshark_service.validate_display_filter(tshark, display)
        if not ok:
            raise HTTPException(400, f"tshark 校验失败:{err}")
        nos = tshark_service.filtered_frame_numbers(tshark, cap["path"], display)
        total = len(nos)
        rows = _load_rows(capture_id, nos=nos[offset:offset + limit], limit=limit)
    else:
        total = db.query_one("SELECT COUNT(*) AS c FROM frames WHERE capture_id=?",
                             (capture_id,))["c"]
        rows = _load_rows(capture_id, offset=offset, limit=limit)
    return {"total": total, "frames": rows}


@router.get("/captures/{capture_id}/frames/{no}/detail")
def frame_detail(capture_id: str, no: int):
    """单帧协议字段树:{no, tree:[{label, children:[...]}]}(树形文本可直接渲染)。"""
    cap = _get_capture(capture_id)
    tshark = _tshark_or_503()
    try:
        return tshark_service.get_frame_tree(tshark, cap["path"], no)
    except KeyError:
        raise HTTPException(404, f"帧 {no} 不存在")
    except Exception as e:
        raise HTTPException(500, f"单帧解析失败:{e}")


# ---------------------------------------------------------------- 统计
@router.get("/captures/{capture_id}/stats/phs")
def stats_phs(capture_id: str):
    cap = _get_capture(capture_id)
    tshark = _tshark_or_503()
    try:
        return {"protocols": tshark_service.get_stats_phs(tshark, cap["path"])}
    except Exception as e:
        raise HTTPException(500, f"协议分级统计失败:{e}")


@router.get("/captures/{capture_id}/stats/io")
def stats_io(capture_id: str, interval: int = Query(1, ge=1, le=3600)):
    cap = _get_capture(capture_id)
    tshark = _tshark_or_503()
    try:
        return {"interval": interval,
                "points": tshark_service.get_stats_io(tshark, cap["path"], interval)}
    except Exception as e:
        raise HTTPException(500, f"IO 统计失败:{e}")


@router.get("/captures/{capture_id}/stats/conversations")
def stats_conversations(capture_id: str, proto: str = Query("tcp")):
    cap = _get_capture(capture_id)
    tshark = _tshark_or_503()
    try:
        return {"proto": proto,
                "conversations": tshark_service.get_stats_conversations(tshark, cap["path"], proto)}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"会话统计失败:{e}")


@router.get("/captures/{capture_id}/follow/{stream}")
def follow_stream(capture_id: str, stream: int, proto: str = Query("tcp")):
    cap = _get_capture(capture_id)
    tshark = _tshark_or_503()
    try:
        return tshark_service.get_follow_messages(tshark, cap["path"], stream, proto)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Follow 失败:{e}")


# ---------------------------------------------------------------- 分析
@router.post("/captures/{capture_id}/analyze")
def analyze(capture_id: str, mode: str = Query("rules")):
    """生成规则报告,或用 mode=ai_direct 跳过本地规则/知识库直接请求 AI。"""
    _get_capture(capture_id)
    try:
        report_id = analysis.analyze_capture(capture_id, mode=mode)
    except KeyError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    return {"report_id": report_id}
